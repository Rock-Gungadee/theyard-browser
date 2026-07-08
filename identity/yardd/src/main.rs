mod peercred;
mod protocol;
mod session;

use protocol::{Reply, Request};
use rand::RngCore;
use rand_core::OsRng;
use session::SessionStore;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, process, thread};
use subtle::ConstantTimeEq;

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    // Async-signal-safe: only sets a flag. All real cleanup (locking
    // identities, removing the socket file) happens in the main loop once
    // it observes this flag, never inside the signal handler itself.
    SHOULD_EXIT.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, handle_signal as usize);
        libc::signal(libc::SIGINT, handle_signal as usize);
    }
}

fn identity_root() -> PathBuf {
    if let Ok(override_root) = std::env::var("YARD_IDENTITY_ROOT") {
        return PathBuf::from(override_root);
    }
    yard_identity::default_root().expect("could not determine identity root (is $HOME set?)")
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Binds the daemon's Unix socket, refusing to start if another yardd
/// instance already has it open, and cleaning up a stale socket file left
/// behind by a crash.
fn bind_socket(socket_path: &PathBuf) -> UnixListener {
    if socket_path.exists() {
        match UnixStream::connect(socket_path) {
            Ok(_) => {
                eprintln!(
                    "yardd: another instance is already listening on {}",
                    socket_path.display()
                );
                process::exit(1);
            }
            Err(_) => {
                // Stale socket file from a previous crash — safe to remove,
                // nothing is listening on it.
                let _ = fs::remove_file(socket_path);
            }
        }
    }

    let listener = UnixListener::bind(socket_path).unwrap_or_else(|e| {
        eprintln!("yardd: failed to bind {}: {e}", socket_path.display());
        process::exit(1);
    });

    // Owner-only. This is defense-in-depth alongside the SO_PEERCRED check —
    // the socket should never be reachable by another local user even if
    // that check were somehow bypassed.
    let perms = fs::Permissions::from_mode(0o600);
    if let Err(e) = fs::set_permissions(socket_path, perms) {
        eprintln!("yardd: warning: could not set socket permissions: {e}");
    }

    listener
}

fn handle_connection(
    stream: UnixStream,
    store: Arc<SessionStore>,
    root: PathBuf,
    token: Arc<String>,
) {
    // Kernel-verified: refuse the connection outright if it's not from our
    // own OS user, before a single byte of the request is even parsed.
    match peercred::peer_uid(&stream) {
        Ok(uid) if uid == peercred::own_uid() => {}
        Ok(_) => {
            eprintln!("yardd: rejected connection from a different OS user");
            return;
        }
        Err(e) => {
            eprintln!("yardd: could not verify peer credentials: {e}");
            return;
        }
    }

    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let reader = BufReader::new(stream);

    for line in reader.lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };

        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(request) => {
                if !token_matches(request.token(), &token) {
                    Reply::err("invalid session token")
                } else {
                    let is_shutdown = matches!(request, Request::Shutdown { .. });
                    let reply = dispatch(request, &store, &root);
                    if is_shutdown {
                        store.lock_all();
                        SHOULD_EXIT.store(true, Ordering::SeqCst);
                    }
                    reply
                }
            }
            Err(e) => Reply::err(format!("malformed request: {e}")),
        };

        let Ok(mut serialized) = serde_json::to_string(&reply) else {
            break;
        };
        serialized.push('\n');
        if writer.write_all(serialized.as_bytes()).is_err() {
            break;
        }
        if writer.flush().is_err() {
            break;
        }
    }
}

/// Constant-time token comparison. The socket is already gated by
/// filesystem permissions and SO_PEERCRED, so a timing side-channel here
/// isn't the most likely attack — but there's no cost to closing it too.
fn token_matches(given: &str, expected: &str) -> bool {
    given.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn dispatch(request: Request, store: &SessionStore, root: &PathBuf) -> Reply {
    match request {
        Request::CreateProfile { label, passphrase, .. } => {
            match yard_identity::create_profile(root, label.as_deref(), &passphrase) {
                Ok(meta) => Reply::ok(serde_json::json!({
                    "peer_id": meta.peer_id,
                    "label": meta.label,
                    "created_at_unix": meta.created_at_unix,
                })),
                Err(e) => Reply::err(e.to_string()),
            }
        }

        Request::ListProfiles { .. } => match yard_identity::list_profiles(root) {
            Ok(profiles) => {
                let list: Vec<_> = profiles
                    .into_iter()
                    .map(|p| serde_json::json!({ "peer_id": p.peer_id, "label": p.label }))
                    .collect();
                Reply::ok(serde_json::json!({ "profiles": list }))
            }
            Err(e) => Reply::err(e.to_string()),
        },

        Request::Unlock {
            peer_id,
            passphrase,
            ..
        } => match store.unlock(root, &peer_id, &passphrase) {
            Ok(()) => Reply::ok_empty(),
            Err(e) => Reply::err(e.to_string()),
        },

        Request::Lock { peer_id, .. } => {
            let was_unlocked = store.lock(&peer_id);
            Reply::ok(serde_json::json!({ "was_unlocked": was_unlocked }))
        }

        Request::LockAll { .. } => {
            store.lock_all();
            Reply::ok_empty()
        }

        Request::IsUnlocked { peer_id, .. } => {
            Reply::ok(serde_json::json!({ "unlocked": store.is_unlocked(&peer_id) }))
        }

        Request::Sign {
            peer_id,
            message_hex,
            ..
        } => {
            let message = match hex::decode(&message_hex) {
                Ok(m) => m,
                Err(e) => return Reply::err(format!("invalid message_hex: {e}")),
            };
            match store.sign(&peer_id, &message) {
                Some(sig_bytes) => {
                    Reply::ok(serde_json::json!({ "signature_hex": hex::encode(sig_bytes) }))
                }
                None => Reply::err(format!(
                    "identity {peer_id} is not unlocked — call unlock first"
                )),
            }
        }

        Request::RenameProfile { peer_id, label, .. } => {
            match yard_identity::rename_profile(root, &peer_id, label.as_deref()) {
                Ok(()) => Reply::ok_empty(),
                Err(e) => Reply::err(e.to_string()),
            }
        }

        Request::Shutdown { .. } => Reply::ok_empty(),
    }
}

fn main() {
    install_signal_handlers();

    let root = identity_root();
    if let Err(e) = fs::create_dir_all(&root) {
        eprintln!("yardd: failed to create {}: {e}", root.display());
        process::exit(1);
    }

    let run_dir = root.join("run");
    if let Err(e) = fs::create_dir_all(&run_dir) {
        eprintln!("yardd: failed to create {}: {e}", run_dir.display());
        process::exit(1);
    }
    let _ = fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700));

    let socket_path = run_dir.join("yardd.sock");
    let listener = bind_socket(&socket_path);
    listener
        .set_nonblocking(true)
        .expect("failed to set listener non-blocking");

    let token = generate_token();

    // Startup line: the browser spawns this process and reads exactly one
    // line of JSON from stdout to learn the socket path and session token,
    // then treats stdout as done. Nothing sensitive goes to disk, argv, or
    // an env var another local process could read via /proc/<pid>/environ.
    let startup = serde_json::json!({
        "socket": socket_path.to_string_lossy(),
        "token": token,
        "pid": process::id(),
    });
    println!("{startup}");
    let _ = std::io::stdout().flush();

    let store = Arc::new(SessionStore::new());
    let token = Arc::new(token);

    while !SHOULD_EXIT.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let store = Arc::clone(&store);
                let root = root.clone();
                let token = Arc::clone(&token);
                thread::spawn(move || handle_connection(stream, store, root, token));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(150));
            }
            Err(e) => {
                eprintln!("yardd: accept error: {e}");
            }
        }
    }

    // Reached on SIGTERM/SIGINT or an explicit Shutdown request. Belt and
    // suspenders: lock_all() again even though the Shutdown path already
    // calls it, since a signal-triggered exit skips that.
    store.lock_all();
    let _ = fs::remove_file(&socket_path);
    eprintln!("yardd: shut down cleanly, all identities locked");
}
