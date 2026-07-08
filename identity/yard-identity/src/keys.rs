use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/// Number of hex characters used for a peer ID (first 8 hex chars of
/// SHA-256(public_key), per spec section 5).
pub const PEER_ID_HEX_LEN: usize = 8;

/// A freshly generated (unencrypted, in-memory only) Ed25519 keypair.
/// Callers must encrypt `signing_key` before it touches disk — see
/// `crypto::seal`. This type deliberately does not implement Clone/Debug
/// to reduce the chance of a raw key being copied or logged accidentally.
pub struct GeneratedKeypair {
    pub signing_key: SigningKey,
    pub peer_id: String,
}

/// Generates a new Ed25519 keypair using the OS CSPRNG and derives its peer ID.
pub fn generate_keypair() -> GeneratedKeypair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let peer_id = derive_peer_id(&signing_key.verifying_key());
    GeneratedKeypair {
        signing_key,
        peer_id,
    }
}

/// Derives a peer ID from a public key: first 8 hex chars of SHA-256(pubkey_bytes).
pub fn derive_peer_id(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)[..PEER_ID_HEX_LEN].to_string()
}

/// Signs a message with the given signing key.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verifies a signature against a message and public key.
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify_strict(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_is_eight_lowercase_hex_chars() {
        let kp = generate_keypair();
        assert_eq!(kp.peer_id.len(), PEER_ID_HEX_LEN);
        assert!(kp.peer_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(kp.peer_id, kp.peer_id.to_lowercase());
    }

    #[test]
    fn peer_id_is_deterministic_from_public_key() {
        let kp = generate_keypair();
        let recomputed = derive_peer_id(&kp.signing_key.verifying_key());
        assert_eq!(kp.peer_id, recomputed);
    }

    #[test]
    fn different_keypairs_get_different_peer_ids() {
        let a = generate_keypair();
        let b = generate_keypair();
        assert_ne!(a.peer_id, b.peer_id);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = generate_keypair();
        let msg = b"hello from the yard";
        let sig = sign(&kp.signing_key, msg);
        assert!(verify(&kp.signing_key.verifying_key(), msg, &sig));
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let kp = generate_keypair();
        let sig = sign(&kp.signing_key, b"original message");
        assert!(!verify(
            &kp.signing_key.verifying_key(),
            b"tampered message",
            &sig
        ));
    }
}
