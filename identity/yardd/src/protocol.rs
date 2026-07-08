use serde::{Deserialize, Serialize};

/// One request per line of JSON on the socket. Every variant carries `token`
/// — the per-launch session token the browser received on daemon startup.
/// Requests missing or with a wrong token are rejected before any other
/// field is even looked at.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Create a brand-new identity. Does not unlock/hold it afterward —
    /// call `Unlock` separately if the caller wants to sign immediately.
    CreateProfile {
        token: String,
        label: Option<String>,
        passphrase: String,
    },

    /// List local profiles (peer_id + label only) for a "who's this?" picker.
    /// No passphrase needed, but still gated by the session token.
    ListProfiles { token: String },

    /// Unlock an identity for this daemon session. On success the signing
    /// key is held in memory until `Lock`, `LockAll`, or daemon exit.
    Unlock {
        token: String,
        peer_id: String,
        passphrase: String,
    },

    /// Explicitly forget an unlocked identity's key material before any
    /// timeout would. This exists from day one — not bolted on later —
    /// because "no way to lock early" is the first thing a careful user
    /// will ask about.
    Lock { token: String, peer_id: String },

    /// Forget all unlocked identities at once (e.g. "lock everything" action).
    LockAll { token: String },

    /// Check whether a given identity is currently unlocked, without
    /// revealing anything about identities that don't exist locally
    /// vs. exist-but-locked (both simply report `unlocked: false`).
    IsUnlocked { token: String, peer_id: String },

    /// Sign a message with a currently-unlocked identity. `message_hex` is
    /// the message bytes, hex-encoded, to keep the wire format plain JSON
    /// text with no binary/base64 ambiguity.
    Sign {
        token: String,
        peer_id: String,
        message_hex: String,
    },

    /// Change a profile's local display label. Never touches the peer ID
    /// or the encrypted key file.
    RenameProfile {
        token: String,
        peer_id: String,
        label: Option<String>,
    },

    /// Graceful shutdown: locks everything, closes the socket, exits.
    /// The browser can also just kill the process on exit — this exists
    /// for a clean "sign out" action distinct from "browser crashed".
    Shutdown { token: String },
}

impl Request {
    pub fn token(&self) -> &str {
        match self {
            Request::CreateProfile { token, .. }
            | Request::ListProfiles { token }
            | Request::Unlock { token, .. }
            | Request::Lock { token, .. }
            | Request::LockAll { token }
            | Request::IsUnlocked { token, .. }
            | Request::Sign { token, .. }
            | Request::RenameProfile { token, .. }
            | Request::Shutdown { token } => token,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub data: Option<serde_json::Value>,
}

impl Reply {
    pub fn ok(data: serde_json::Value) -> Self {
        Reply {
            ok: true,
            error: None,
            data: Some(data),
        }
    }

    pub fn ok_empty() -> Self {
        Reply {
            ok: true,
            error: None,
            data: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Reply {
            ok: false,
            error: Some(message.into()),
            data: None,
        }
    }
}
