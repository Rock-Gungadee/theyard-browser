use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("a profile already exists at {0}")]
    ProfileAlreadyExists(PathBuf),

    #[error("no profile found for peer id {0}")]
    ProfileNotFound(String),

    #[error("incorrect passphrase")]
    IncorrectPassphrase,

    #[error("passphrase must be at least {min} characters (got {got})")]
    PassphraseTooShort { min: usize, got: usize },

    #[error("label must not be empty")]
    EmptyLabel,

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to (de)serialize profile metadata: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("encryption failed")]
    Encryption,

    #[error("decryption failed — wrong passphrase or corrupted data")]
    Decryption,

    #[error("identity file is corrupted or has an unrecognized format: {0}")]
    CorruptData(String),

    #[error("manifest is corrupted: {0}")]
    CorruptManifest(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;
