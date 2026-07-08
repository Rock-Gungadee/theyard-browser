//! yard-identity — Ed25519 identity, encrypted local profile storage, and
//! signing for The Yard network (spec section 5).
//!
//! This crate is intentionally standalone: no networking, no sockets, no
//! Gecko/browser dependency. It is Milestone 3A — a tested library that a
//! later daemon (`yardd`) will wrap over a local socket for the browser to
//! talk to. Nothing here assumes how it will be called.
//!
//! ## Design decisions baked into this crate
//! - **Peer ID** = first 8 hex chars of SHA-256(public key). Permanent,
//!   never changes for a given keypair.
//! - **Profiles are keyed by peer ID on disk**, not by label — labels are
//!   free-form, editable metadata. See `storage` module docs.
//! - **No recovery.** There is no master key, no reset mechanism. Losing the
//!   passphrase means losing the identity. This is intentional per spec
//!   section 5 ("this is not a bug").
//! - **One machine, many identities.** `~/.yard/profiles/<peer_id>/` supports
//!   multiple local identities the way an old multi-user system would.
//!
//! ## What this crate does NOT do
//! - No display-name registration on the network ledger (that's Chat 4).
//! - No import/export or multi-device sync (future milestone; the on-disk
//!   identity file format is already self-contained to make that cheap
//!   later).
//! - No daemon, no IPC, no browser integration (Milestone 3B/3C).

pub mod crypto;
pub mod error;
pub mod keys;
pub mod profile;
pub mod storage;

// Flat re-exports for ergonomic top-level use, e.g. `yard_identity::create_profile(...)`.
pub use error::{IdentityError, Result};
pub use profile::{create_profile, default_root, list_profiles, rename_profile, unlock_profile, SigningContext};
pub use storage::{ManifestEntry, ProfileMetadata};
