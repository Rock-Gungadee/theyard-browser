# yard-identity

Milestone 3A of The Yard: a standalone Rust library for Ed25519 identity
generation, encrypted local storage, and signing. No networking, no sockets,
no Gecko dependency — this is the tested foundation that Milestone 3B (a
small `yardd` process) and 3C (Gecko talking to it over a local socket) will
build on top of.

## What it does

- Generates an Ed25519 keypair (`ed25519-dalek`, backed by the OS CSPRNG)
- Derives the peer ID: first 8 hex chars of SHA-256(public key) — spec §5
- Encrypts the private key at rest with Argon2id (64 MiB, 3 passes) → ChaCha20-Poly1305
- Stores one identity per directory, keyed by peer ID, under `~/.yard/profiles/`
- Supports multiple local identities on one machine, each independently locked
- Signs and verifies messages once a profile is unlocked

## What it deliberately does not do

- No password reset / recovery. Losing the passphrase loses the identity — that's the design, not a bug (spec §5).
- No display-name registration on the network ledger (Chat 4 territory).
- No daemon, no IPC, no multi-device sync yet.

## On-disk layout

```
~/.yard/
└── profiles/
    ├── 83a91f42/
    │   ├── identity.enc     # encrypted private key (JSON: salt, nonce, ciphertext, argon2 params)
    │   └── profile.json     # { peer_id, label, created_at_unix }
    ├── 91af32bd/
    │   ├── identity.enc
    │   └── profile.json
    └── manifest.json        # [{ peer_id, label }, ...] — no secrets, safe to read for a picker UI
```

Directories are keyed by **peer ID**, not label. Labels live in `profile.json`
and `manifest.json` and can be changed freely (`rename_profile`) without
touching the identity file or moving anything on disk.

The `identity.enc` format carries its own Argon2 parameters and a version tag,
so tightening the KDF cost later doesn't break existing profiles — old files
just get read with their original params.

## API

```rust
use yard_identity::{create_profile, unlock_profile, default_root};

// Create a new identity (label is optional — spec allows peer-ID-only users)
let root = default_root()?;
let meta = create_profile(&root, Some("Blake"), "a long unique passphrase")?;
println!("your peer id: {}", meta.peer_id);

// Later, unlock it to sign something
let ctx = unlock_profile(&root, &meta.peer_id, "a long unique passphrase")?;
let signature = ctx.sign(b"some message");
```

`SigningContext` holds the decrypted signing key only in memory and wipes it
on drop (`ed25519-dalek`'s `zeroize` feature). The private key is never
returned to a caller directly — only signatures and the public peer ID.

## Running tests

```bash
cargo test
```

24 tests cover: keypair/peer-ID generation and determinism, seal/unseal
roundtrips, wrong-passphrase rejection, tampered-ciphertext rejection, profile
creation/collision handling, manifest integrity, label renaming, crash-safety
(a failed manifest write rolls back the profile directory rather than leaving
an orphan), and cross-profile signature isolation.

Note: Argon2 at these parameters takes roughly 0.3–1s per seal/unseal on
typical hardware — that's intentional (it's a one-time unlock cost, not a
hot path) but it does mean the test suite takes ~50s to run, mostly spent in
Argon2 across the ~10 tests that seal or unseal a key.

## Toolchain note

This was built and tested against **rustc/cargo 1.75** (Ubuntu 24.04's apt
package). A few dependencies had to be pinned in `Cargo.toml` because their
newer releases require Rust 2024 edition support (`edition2024`), which 1.75
doesn't have:

- `ed25519-dalek = "=2.1.1"` (2.2.0 requires rustc 1.81+)
- `zeroize = "=1.6.0"`
- `base64ct = "=1.6.0"` (transitive, via `argon2`)
- `tempfile = "=3.10.1"` (dev-dependency only, transitive `getrandom` issue)

If the Hetzner build box has a newer rustc (check with `rustc --version`),
these pins can likely be loosened — try `cargo update` and rerun `cargo test`
to confirm nothing regresses before removing a pin.

## Where this goes next

- **3B**: wrap this crate in a tiny `yardd` process spawned by the browser
  (not a long-running background service — see chat notes on the socket
  security model: per-session auth token, daemon dies when the browser closes)
- **3C**: `yard://identity/setup` and `yard://identity/unlock` pages in Gecko
  talk to `yardd` over a local socket
