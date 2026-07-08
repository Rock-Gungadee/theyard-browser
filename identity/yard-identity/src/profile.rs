use crate::crypto::{self, ARGON2_M_COST_KIB, ARGON2_P_COST, ARGON2_T_COST};
use crate::error::{IdentityError, Result};
use crate::keys::{self, GeneratedKeypair};
use crate::storage::{self, ProfileMetadata};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

/// An unlocked identity, held only in memory. Dropping this zeroizes the
/// signing key (ed25519-dalek's "zeroize" feature wipes it on drop). Nothing
/// in this struct is ever written back to disk — unlocking only reads.
pub struct SigningContext {
    signing_key: SigningKey,
    pub peer_id: String,
}

impl SigningContext {
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        keys::sign(&self.signing_key, message)
    }
}

/// Creates a new identity: generates an Ed25519 keypair, encrypts it under
/// `passphrase`, and writes it to `root/profiles/<peer_id>/`. `label` is
/// optional per spec section 5 — a user may remain peer-ID only.
///
/// This does three things that must all succeed together (generate, seal,
/// persist) — `storage::write_new_profile` handles rolling back the profile
/// directory if the manifest update fails, so callers never see a half-created
/// profile on disk.
pub fn create_profile(
    root: &Path,
    label: Option<&str>,
    passphrase: &str,
) -> Result<ProfileMetadata> {
    if let Some(l) = label {
        if l.trim().is_empty() {
            return Err(IdentityError::EmptyLabel);
        }
    }
    crypto::validate_passphrase_len(passphrase)?;

    let GeneratedKeypair {
        signing_key,
        peer_id,
    } = keys::generate_keypair();

    let seal_result = crypto::seal(passphrase, signing_key.as_bytes());
    // signing_key is dropped here regardless of seal outcome; the
    // "zeroize" feature on ed25519-dalek wipes it from memory.
    let sealed = seal_result?;

    storage::write_new_profile(
        root,
        &peer_id,
        label,
        &sealed,
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )
}

/// Unlocks an existing profile with its passphrase, returning a
/// `SigningContext` usable for signing. Fails with
/// `IdentityError::Decryption` on a wrong passphrase — never with a more
/// specific error, so we don't leak whether the peer ID exists via timing
/// or error-type differences beyond what `ProfileNotFound` already reveals.
pub fn unlock_profile(root: &Path, peer_id: &str, passphrase: &str) -> Result<SigningContext> {
    let (sealed, _m, _t, _p) = storage::load_sealed(root, peer_id)?;
    let plaintext = crypto::unseal(passphrase, &sealed)?;

    let key_bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::CorruptData("decrypted key has wrong length".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Sanity check: the peer ID derived from the unlocked key should match
    // the directory we loaded it from. A mismatch means disk corruption or
    // tampering, not a wrong passphrase (which would already have failed
    // at the AEAD decryption step above).
    let derived = keys::derive_peer_id(&signing_key.verifying_key());
    if derived != peer_id {
        return Err(IdentityError::CorruptData(
            "unlocked key does not match its profile's peer id".to_string(),
        ));
    }

    Ok(SigningContext {
        signing_key,
        peer_id: peer_id.to_string(),
    })
}

/// Lists local profiles for a "who's this?" picker — no passphrase needed.
pub fn list_profiles(root: &Path) -> Result<Vec<storage::ManifestEntry>> {
    storage::list_profiles(root)
}

/// Renames a profile's local display label. Does not touch the peer ID, the
/// profile directory, or the private key. This is purely local metadata —
/// registering a name on the network ledger is a separate, later operation.
pub fn rename_profile(root: &Path, peer_id: &str, new_label: Option<&str>) -> Result<()> {
    if let Some(l) = new_label {
        if l.trim().is_empty() {
            return Err(IdentityError::EmptyLabel);
        }
    }
    storage::update_label(root, peer_id, new_label)
}

/// Convenience wrapper around `storage::default_root` for callers that don't
/// need a custom root (i.e. everyone except tests).
pub fn default_root() -> Result<PathBuf> {
    storage::default_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_then_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let meta = create_profile(root, Some("Blake"), "correct horse battery staple").unwrap();
        let ctx = unlock_profile(root, &meta.peer_id, "correct horse battery staple").unwrap();

        assert_eq!(ctx.peer_id, meta.peer_id);
        let msg = b"a message from the yard";
        let sig = ctx.sign(msg);
        assert!(keys::verify(&ctx.verifying_key(), msg, &sig));
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let meta = create_profile(root, None, "correct horse battery staple").unwrap();

        let result = unlock_profile(root, &meta.peer_id, "totally wrong phrase");
        assert!(matches!(result, Err(IdentityError::Decryption)));
    }

    #[test]
    fn unlock_nonexistent_peer_id_fails() {
        let dir = tempdir().unwrap();
        let result = unlock_profile(dir.path(), "deadbeef", "whatever passphrase");
        assert!(matches!(result, Err(IdentityError::ProfileNotFound(_))));
    }

    #[test]
    fn create_without_label_is_allowed() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let meta = create_profile(root, None, "correct horse battery staple").unwrap();
        assert!(meta.label.is_none());

        let profiles = list_profiles(root).unwrap();
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].label.is_none());
    }

    #[test]
    fn create_with_empty_label_rejected() {
        let dir = tempdir().unwrap();
        let result = create_profile(dir.path(), Some("   "), "correct horse battery staple");
        assert!(matches!(result, Err(IdentityError::EmptyLabel)));
    }

    #[test]
    fn create_with_short_passphrase_rejected() {
        let dir = tempdir().unwrap();
        let result = create_profile(dir.path(), None, "short");
        assert!(matches!(
            result,
            Err(IdentityError::PassphraseTooShort { .. })
        ));
    }

    #[test]
    fn two_profiles_on_one_machine_have_independent_keys() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let a = create_profile(root, Some("Alice"), "correct horse battery staple").unwrap();
        let b = create_profile(root, Some("Bob"), "another good passphrase").unwrap();

        assert_ne!(a.peer_id, b.peer_id);

        let ctx_a = unlock_profile(root, &a.peer_id, "correct horse battery staple").unwrap();
        let ctx_b = unlock_profile(root, &b.peer_id, "another good passphrase").unwrap();

        let sig_a = ctx_a.sign(b"same message");
        // Signature from A must not verify against B's key.
        assert!(!keys::verify(&ctx_b.verifying_key(), b"same message", &sig_a));
    }

    #[test]
    fn rename_changes_label_without_changing_peer_id() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let meta = create_profile(root, Some("Blake"), "correct horse battery staple").unwrap();

        rename_profile(root, &meta.peer_id, Some("Blake the Builder")).unwrap();

        let profiles = list_profiles(root).unwrap();
        let entry = profiles.iter().find(|p| p.peer_id == meta.peer_id).unwrap();
        assert_eq!(entry.label.as_deref(), Some("Blake the Builder"));
    }
}
