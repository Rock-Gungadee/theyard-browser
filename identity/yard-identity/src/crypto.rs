use crate::error::{IdentityError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rand_core::OsRng;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Argon2id parameters. Deliberately heavier than typical web-login defaults
/// (64 MiB memory, 3 passes) since this runs once per unlock, not per request,
/// and it's the only thing standing between an attacker and a stolen private key.
pub const ARGON2_M_COST_KIB: u32 = 65536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Result of sealing a private key: everything needed to write to disk,
/// and everything needed to later unseal it (except the passphrase itself).
pub struct SealedKey {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Encrypts `plaintext` (the raw 32-byte Ed25519 signing key) under a key
/// derived from `passphrase` via Argon2id. Generates a fresh random salt and
/// nonce internally — callers never choose or reuse these.
pub fn seal(passphrase: &str, plaintext: &[u8]) -> Result<SealedKey> {
    validate_passphrase_len(passphrase)?;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| IdentityError::Encryption)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| IdentityError::Encryption)?;

    key.zeroize();

    Ok(SealedKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts a sealed key given the passphrase. Returns `IdentityError::Decryption`
/// on wrong passphrase or corrupted/tampered ciphertext — ChaCha20-Poly1305's
/// authentication tag makes these indistinguishable by design, which is correct:
/// we don't want to leak which one it was.
pub fn unseal(passphrase: &str, sealed: &SealedKey) -> Result<Vec<u8>> {
    let mut key = derive_key(passphrase, &sealed.salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| IdentityError::Decryption)?;
    let nonce = Nonce::from_slice(&sealed.nonce);

    let result = cipher
        .decrypt(nonce, sealed.ciphertext.as_ref())
        .map_err(|_| IdentityError::Decryption);

    key.zeroize();
    result
}

pub fn validate_passphrase_len(passphrase: &str) -> Result<()> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(IdentityError::PassphraseTooShort {
            min: MIN_PASSPHRASE_LEN,
            got: passphrase.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let plaintext = b"0123456789abcdef0123456789abcdef";
        let sealed = seal("correct horse battery staple", plaintext).unwrap();
        let opened = unseal("correct horse battery staple", &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let plaintext = b"secret key bytes go here 123456";
        let sealed = seal("correct horse battery staple", plaintext).unwrap();
        let result = unseal("wrong passphrase entirely", &sealed);
        assert!(matches!(result, Err(IdentityError::Decryption)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let plaintext = b"secret key bytes go here 123456";
        let mut sealed = seal("correct horse battery staple", plaintext).unwrap();
        sealed.ciphertext[0] ^= 0xFF;
        let result = unseal("correct horse battery staple", &sealed);
        assert!(matches!(result, Err(IdentityError::Decryption)));
    }

    #[test]
    fn short_passphrase_rejected() {
        let result = seal("short", b"whatever");
        assert!(matches!(
            result,
            Err(IdentityError::PassphraseTooShort { .. })
        ));
    }

    #[test]
    fn each_seal_uses_fresh_salt_and_nonce() {
        let a = seal("correct horse battery staple", b"same plaintext here").unwrap();
        let b = seal("correct horse battery staple", b"same plaintext here").unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
