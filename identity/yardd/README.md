# yardd

Milestone 3B of The Yard: a small local daemon that wraps `yard-identity`
behind a Unix domain socket, in the same trust model as `ssh-agent` or
`gpg-agent`. The browser (Milestone 3C) spawns this as a child process and
talks to it over the socket — it never touches private key bytes directly.

## Security model

- **Process lifecycle**: the browser spawns `yardd` as a child process on
  launch and is expected to kill it (or send a `shutdown` request) when the
  browser exits. `yardd` does not daemonize itself, does not fork into the
  background, and does not persist across browser restarts — no "is it
  already running?" problem, because the browser owns its lifetime.

- **The socket**: a Unix domain socket at `~/.yard/run/yardd.sock`
  (or `$YARD_IDENTITY_ROOT/run/yardd.sock` if that env var is set — see
  Testing below). Never TCP, never bound to any network interface. The
  socket file is `chmod 0600` and its parent directory `chmod 0700`.

- **Per-launch session token**: `yardd` generates a random 32-byte token at
  startup and prints it, along with the socket path, as a single line of
  JSON on stdout — nothing sensitive touches disk, argv, or an environment
  variable another local process could read via `/proc/<pid>/environ`. The
  browser reads that one line at spawn time and must include the token on
  every request. A wrong or missing token gets a generic `invalid session
  token` error — no distinction is made between "wrong token" and other
  failure modes that would help an attacker narrow things down.

- **SO_PEERCRED check**: on top of the token, every connection is checked at
  the kernel level — `getsockopt(SO_PEERCRED)` — to confirm the connecting
  process is running as the same OS user as `yardd` itself. This can't be
  spoofed by the connecting process; it's the same defense-in-depth `ssh-agent`
  and Docker's socket-based APIs rely on. Filesystem permissions on the
  socket are the first line of defense; this is the second.

- **Session-held keys, not re-sent-every-time**: once a profile is unlocked,
  its signing key stays in daemon memory (not on disk, not sent back to the
  browser) until explicitly locked or the daemon exits. The alternative —
  re-sending the passphrase on every sign request — was considered and
  rejected: it doesn't remove the "who holds the secret" problem, it just
  forces the browser to cache the passphrase somewhere to keep the UX usable,
  which is a worse place for it to live than a daemon built for exactly this.

- **Explicit lock, from day one**: `lock` and `lock_all` commands exist now,
  before any idle-timeout policy is decided. A security-conscious user
  should be able to end a session on demand; that shouldn't wait on a later
  milestone. Idle-timeout / auto-lock-on-sleep can be added later as a purely
  additive protocol change.

- **Signal handling**: `SIGTERM`/`SIGINT` trigger a graceful shutdown —
  all unlocked identities are cleared from memory (dropping each
  `SigningContext`, which zeroizes via `ed25519-dalek`'s `zeroize` feature)
  and the socket file is removed before the process exits. The signal
  handler itself only sets an atomic flag (async-signal-safe); the actual
  cleanup runs in the main loop once it observes that flag.

- **Crash recovery**: if `yardd` is killed (`SIGKILL`, OOM, crash) without
  cleanup, it leaves a stale socket file behind. On next startup, `yardd`
  tries connecting to any existing socket file at its path — a successful
  connect means another live instance owns it and this one refuses to start;
  a failed connect means the file is stale and safe to remove and rebind.

## Wire protocol

Newline-delimited JSON over the Unix socket. One request per line, one reply
per line, connection can be kept open for multiple requests.

**Startup line** (stdout, once, at process start):
```json
{"socket": "/home/user/.yard/run/yardd.sock", "token": "<64 hex chars>", "pid": 12345}
```

**Requests** — every request needs `"token"`:

| cmd | fields | does |
|---|---|---|
| `create_profile` | `label?`, `passphrase` | generates + stores a new identity, does not unlock it |
| `list_profiles` | — | returns `{peer_id, label}` for all local profiles, no passphrase needed |
| `unlock` | `peer_id`, `passphrase` | decrypts and holds the key in memory for this session |
| `lock` | `peer_id` | forgets one unlocked identity |
| `lock_all` | — | forgets all unlocked identities |
| `is_unlocked` | `peer_id` | `{"unlocked": bool}` |
| `sign` | `peer_id`, `message_hex` | signs hex-encoded bytes with an unlocked identity |
| `rename_profile` | `peer_id`, `label?` | changes the local display label only |
| `shutdown` | — | locks everything, then daemon exits |

**Replies**: `{"ok": true, ...data}` or `{"ok": false, "error": "..."}`.

Example session:
```
→ {"cmd":"create_profile","token":"...","label":"Blake","passphrase":"correct horse battery staple"}
← {"ok":true,"peer_id":"83a91f42","label":"Blake","created_at_unix":1783482898}

→ {"cmd":"unlock","token":"...","peer_id":"83a91f42","passphrase":"correct horse battery staple"}
← {"ok":true}

→ {"cmd":"sign","token":"...","peer_id":"83a91f42","message_hex":"68656c6c6f"}
← {"ok":true,"signature_hex":"88e16a55...b1390f"}
```

## Testing locally

`yardd` respects `YARD_IDENTITY_ROOT` as an override for where profiles and
the run directory live (defaults to `~/.yard`), which is what lets you test
without touching a real home directory:

```bash
export YARD_IDENTITY_ROOT=/tmp/yard-test/.yard
./target/debug/yardd
# read the startup JSON line for the socket path + token, then drive it
# with any Unix-socket client (python's `socket` module, socat, etc.)
```

This was exercised end-to-end during development: full create → unlock →
sign → lock lifecycle, wrong-passphrase rejection, wrong-token rejection,
sign-before-unlock rejection, malformed-JSON handling, and the stale-socket
crash-recovery path (`kill -9` then restart) — all behaved as designed.

## Toolchain note

Built against rustc/cargo 1.75 (see `yard-identity/README.md` for the same
note) — no additional version pins were needed beyond what that crate already
requires; `yardd`'s own new dependencies (`libc`, `subtle`) built fine
against 1.75 at the versions in `Cargo.toml`.

## Where this goes next (3C)

Gecko-side `yard://identity/setup` and `yard://identity/unlock` pages need:
1. Browser-chrome code to spawn `yardd` as a child process at browser launch
   and capture its stdout to get the socket path + token
2. A Unix-socket client in Gecko (or the sidecar-daemon-adjacent Rust code)
   to send requests and parse replies
3. Wiring the "Create your identity" / "Unlock YARD" UI screens to those
   requests
4. Killing (or sending `shutdown` to) the `yardd` child process on browser
   exit
