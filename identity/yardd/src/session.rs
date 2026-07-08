use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use yard_identity::{unlock_profile, IdentityError, SigningContext};

/// Holds unlocked identities for the lifetime of this daemon process (or
/// until explicitly locked). This is the SSH-agent-style trust boundary:
/// the browser never sees private key bytes, only signatures — but the
/// daemon itself must be trusted while an identity is unlocked, same as
/// ssh-agent must be trusted while it holds a decrypted key.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, SigningContext>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn unlock(
        &self,
        root: &Path,
        peer_id: &str,
        passphrase: &str,
    ) -> Result<(), IdentityError> {
        let ctx = unlock_profile(root, peer_id, passphrase)?;
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .insert(peer_id.to_string(), ctx);
        Ok(())
    }

    /// Returns true if the identity was unlocked (and is now locked).
    /// Returns false if it wasn't unlocked to begin with — not an error,
    /// locking an already-locked identity is a no-op.
    pub fn lock(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .remove(peer_id)
            .is_some()
    }

    pub fn lock_all(&self) {
        self.sessions.lock().expect("session mutex poisoned").clear();
    }

    pub fn is_unlocked(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .contains_key(peer_id)
    }

    /// Signs `message` with `peer_id`'s key if currently unlocked.
    /// Returns None if not unlocked — caller turns that into a clear
    /// "identity not unlocked" error rather than guessing why.
    pub fn sign(&self, peer_id: &str, message: &[u8]) -> Option<Vec<u8>> {
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .get(peer_id)
            .map(|ctx| ctx.sign(message).to_bytes().to_vec())
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
