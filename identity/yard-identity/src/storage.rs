use crate::crypto::{SealedKey, NONCE_LEN, SALT_LEN};
use crate::error::{IdentityError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const IDENTITY_FILE_NAME: &str = "identity.enc";
const PROFILE_FILE_NAME: &str = "profile.json";
const MANIFEST_FILE_NAME: &str = "manifest.json";
const IDENTITY_FORMAT_VERSION: u8 = 1;

/// On-disk (JSON) representation of a sealed private key. Field names and the
/// `version` tag are part of the format contract — changing crypto defaults
/// later must bump `version` and keep old versions readable.
#[derive(Serialize, Deserialize)]
struct IdentityFileV1 {
    version: u8,
    algorithm: String,
    argon2_m_cost_kib: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Public, non-secret metadata about a profile. Safe to read without a passphrase.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileMetadata {
    pub peer_id: String,
    pub label: Option<String>,
    pub created_at_unix: u64,
}

/// One row in the manifest — enough to render a "who's this?" picker
/// without decrypting anything.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ManifestEntry {
    pub peer_id: String,
    pub label: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    profiles: Vec<ManifestEntry>,
}

fn io_err(path: &Path, source: std::io::Error) -> IdentityError {
    IdentityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Default root: `~/.yard`. Callers that want testability should pass an
/// explicit root instead of relying on this.
pub fn default_root() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            IdentityError::Io {
                path: PathBuf::from("$HOME"),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "could not determine home directory",
                ),
            }
        })?;
    Ok(PathBuf::from(home).join(".yard"))
}

fn profiles_dir(root: &Path) -> PathBuf {
    root.join("profiles")
}

fn profile_dir(root: &Path, peer_id: &str) -> PathBuf {
    profiles_dir(root).join(peer_id)
}

fn identity_path(root: &Path, peer_id: &str) -> PathBuf {
    profile_dir(root, peer_id).join(IDENTITY_FILE_NAME)
}

fn profile_json_path(root: &Path, peer_id: &str) -> PathBuf {
    profile_dir(root, peer_id).join(PROFILE_FILE_NAME)
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join(MANIFEST_FILE_NAME)
}

/// Writes `contents` to `path` atomically: write to a sibling temp file, then
/// rename over the target. Rename is atomic on the same filesystem, so a crash
/// mid-write can never leave a half-written manifest or profile file.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents).map_err(|e| io_err(&tmp_path, e))?;
    fs::rename(&tmp_path, path).map_err(|e| io_err(path, e))?;
    Ok(())
}

pub fn profile_exists(root: &Path, peer_id: &str) -> bool {
    identity_path(root, peer_id).is_file()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Creates the on-disk profile directory, identity.enc, and profile.json, then
/// appends the profile to manifest.json. If the manifest write fails after the
/// files are written, the newly created profile directory is removed so we
/// never leave an orphaned folder with no manifest entry, or vice versa.
pub fn write_new_profile(
    root: &Path,
    peer_id: &str,
    label: Option<&str>,
    sealed: &SealedKey,
    argon2_m_cost_kib: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
) -> Result<ProfileMetadata> {
    if profile_exists(root, peer_id) {
        return Err(IdentityError::ProfileAlreadyExists(profile_dir(
            root, peer_id,
        )));
    }

    let dir = profile_dir(root, peer_id);
    fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;

    let identity_file = IdentityFileV1 {
        version: IDENTITY_FORMAT_VERSION,
        algorithm: "argon2id-chacha20poly1305".to_string(),
        argon2_m_cost_kib,
        argon2_t_cost,
        argon2_p_cost,
        salt: hex::encode(sealed.salt),
        nonce: hex::encode(sealed.nonce),
        ciphertext: hex::encode(&sealed.ciphertext),
    };
    let identity_json = serde_json::to_vec_pretty(&identity_file)?;

    let metadata = ProfileMetadata {
        peer_id: peer_id.to_string(),
        label: label.map(|s| s.to_string()),
        created_at_unix: now_unix(),
    };
    let metadata_json = serde_json::to_vec_pretty(&metadata)?;

    // If either write fails, clean up the directory we just created rather
    // than leaving a partial profile behind.
    let write_result = (|| -> Result<()> {
        write_atomic(&identity_path(root, peer_id), &identity_json)?;
        write_atomic(&profile_json_path(root, peer_id), &metadata_json)?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }

    if let Err(e) = append_to_manifest(root, &metadata) {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }

    Ok(metadata)
}

fn read_manifest(root: &Path) -> Result<Manifest> {
    let path = manifest_path(root);
    if !path.is_file() {
        return Ok(Manifest::default());
    }
    let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| IdentityError::CorruptManifest(e.to_string()))
}

fn append_to_manifest(root: &Path, metadata: &ProfileMetadata) -> Result<()> {
    fs::create_dir_all(root).map_err(|e| io_err(root, e))?;
    let mut manifest = read_manifest(root)?;

    if manifest.profiles.iter().any(|p| p.peer_id == metadata.peer_id) {
        // Already present (shouldn't happen given profile_exists check, but
        // keep the manifest idempotent rather than duplicating an entry).
        return Ok(());
    }

    manifest.profiles.push(ManifestEntry {
        peer_id: metadata.peer_id.clone(),
        label: metadata.label.clone(),
    });

    let bytes = serde_json::to_vec_pretty(&manifest)?;
    write_atomic(&manifest_path(root), &bytes)
}

/// Updates the label for an existing profile in both profile.json and
/// manifest.json. This is the operation a future "rename identity" UI calls —
/// it never touches the profile directory name or the identity file.
pub fn update_label(root: &Path, peer_id: &str, new_label: Option<&str>) -> Result<()> {
    let meta_path = profile_json_path(root, peer_id);
    if !meta_path.is_file() {
        return Err(IdentityError::ProfileNotFound(peer_id.to_string()));
    }
    let bytes = fs::read(&meta_path).map_err(|e| io_err(&meta_path, e))?;
    let mut metadata: ProfileMetadata = serde_json::from_slice(&bytes)
        .map_err(|e| IdentityError::CorruptData(e.to_string()))?;
    metadata.label = new_label.map(|s| s.to_string());
    let updated = serde_json::to_vec_pretty(&metadata)?;
    write_atomic(&meta_path, &updated)?;

    let mut manifest = read_manifest(root)?;
    if let Some(entry) = manifest.profiles.iter_mut().find(|p| p.peer_id == peer_id) {
        entry.label = new_label.map(|s| s.to_string());
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    write_atomic(&manifest_path(root), &manifest_bytes)
}

/// Lists all local profiles from the manifest — no passphrase required.
/// This is what powers the "who's this?" picker screen.
pub fn list_profiles(root: &Path) -> Result<Vec<ManifestEntry>> {
    Ok(read_manifest(root)?.profiles)
}

/// Loads the sealed identity bytes for a peer ID, ready to hand to `crypto::unseal`.
pub fn load_sealed(root: &Path, peer_id: &str) -> Result<(SealedKey, u32, u32, u32)> {
    let path = identity_path(root, peer_id);
    if !path.is_file() {
        return Err(IdentityError::ProfileNotFound(peer_id.to_string()));
    }
    let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
    let file: IdentityFileV1 =
        serde_json::from_slice(&bytes).map_err(|e| IdentityError::CorruptData(e.to_string()))?;

    if file.version != IDENTITY_FORMAT_VERSION {
        return Err(IdentityError::CorruptData(format!(
            "unsupported identity file version {}",
            file.version
        )));
    }

    let salt_vec = hex::decode(&file.salt).map_err(|e| IdentityError::CorruptData(e.to_string()))?;
    let nonce_vec =
        hex::decode(&file.nonce).map_err(|e| IdentityError::CorruptData(e.to_string()))?;
    let ciphertext =
        hex::decode(&file.ciphertext).map_err(|e| IdentityError::CorruptData(e.to_string()))?;

    let salt: [u8; SALT_LEN] = salt_vec
        .try_into()
        .map_err(|_| IdentityError::CorruptData("salt has wrong length".to_string()))?;
    let nonce: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| IdentityError::CorruptData("nonce has wrong length".to_string()))?;

    Ok((
        SealedKey {
            salt,
            nonce,
            ciphertext,
        },
        file.argon2_m_cost_kib,
        file.argon2_t_cost,
        file.argon2_p_cost,
    ))
}

pub fn load_profile_metadata(root: &Path, peer_id: &str) -> Result<ProfileMetadata> {
    let path = profile_json_path(root, peer_id);
    if !path.is_file() {
        return Err(IdentityError::ProfileNotFound(peer_id.to_string()));
    }
    let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
    serde_json::from_slice(&bytes).map_err(|e| IdentityError::CorruptData(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use tempfile::tempdir;

    fn sample_sealed() -> SealedKey {
        crypto::seal("correct horse battery staple", b"0123456789abcdef0123456789abcdef")
            .unwrap()
    }

    #[test]
    fn write_and_load_round_trips() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let sealed = sample_sealed();

        write_new_profile(
            root,
            "83a91f42",
            Some("Blake"),
            &sealed,
            crypto::ARGON2_M_COST_KIB,
            crypto::ARGON2_T_COST,
            crypto::ARGON2_P_COST,
        )
        .unwrap();

        let (loaded_sealed, m, t, p) = load_sealed(root, "83a91f42").unwrap();
        assert_eq!(loaded_sealed.salt, sealed.salt);
        assert_eq!(loaded_sealed.nonce, sealed.nonce);
        assert_eq!(loaded_sealed.ciphertext, sealed.ciphertext);
        assert_eq!(m, crypto::ARGON2_M_COST_KIB);
        assert_eq!(t, crypto::ARGON2_T_COST);
        assert_eq!(p, crypto::ARGON2_P_COST);

        let meta = load_profile_metadata(root, "83a91f42").unwrap();
        assert_eq!(meta.label.as_deref(), Some("Blake"));
    }

    #[test]
    fn duplicate_peer_id_rejected() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let sealed = sample_sealed();

        write_new_profile(root, "83a91f42", None, &sealed, 65536, 3, 1).unwrap();
        let second = write_new_profile(root, "83a91f42", None, &sealed, 65536, 3, 1);
        assert!(matches!(second, Err(IdentityError::ProfileAlreadyExists(_))));
    }

    #[test]
    fn manifest_lists_created_profiles_without_secrets() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let sealed = sample_sealed();

        write_new_profile(root, "83a91f42", Some("Blake"), &sealed, 65536, 3, 1).unwrap();
        write_new_profile(root, "91af32bd", None, &sealed, 65536, 3, 1).unwrap();

        let profiles = list_profiles(root).unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.iter().any(|p| p.peer_id == "83a91f42" && p.label.as_deref() == Some("Blake")));
        assert!(profiles.iter().any(|p| p.peer_id == "91af32bd" && p.label.is_none()));
    }

    #[test]
    fn update_label_updates_both_profile_json_and_manifest() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let sealed = sample_sealed();
        write_new_profile(root, "83a91f42", Some("Blake"), &sealed, 65536, 3, 1).unwrap();

        update_label(root, "83a91f42", Some("Blake2")).unwrap();

        let meta = load_profile_metadata(root, "83a91f42").unwrap();
        assert_eq!(meta.label.as_deref(), Some("Blake2"));

        let profiles = list_profiles(root).unwrap();
        let entry = profiles.iter().find(|p| p.peer_id == "83a91f42").unwrap();
        assert_eq!(entry.label.as_deref(), Some("Blake2"));
    }

    #[test]
    fn loading_nonexistent_profile_fails_cleanly() {
        let dir = tempdir().unwrap();
        let result = load_sealed(dir.path(), "deadbeef");
        assert!(matches!(result, Err(IdentityError::ProfileNotFound(_))));
    }

    #[test]
    fn failed_write_does_not_leave_orphaned_directory() {
        // Simulate a corrupt-manifest scenario by pre-creating a manifest.json
        // that isn't valid JSON, so append_to_manifest fails after files are
        // written — the profile directory should be rolled back.
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("manifest.json"), b"not valid json{{{").unwrap();

        let sealed = sample_sealed();
        let result = write_new_profile(root, "83a91f42", None, &sealed, 65536, 3, 1);
        assert!(result.is_err());
        assert!(!profile_dir(root, "83a91f42").exists());
    }
}
