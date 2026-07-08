use std::io;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Reads the connecting peer's credentials off a Unix domain socket via
/// SO_PEERCRED (Linux). This is kernel-verified — it cannot be spoofed by
/// the connecting process — unlike anything the client could claim about
/// itself in the request body.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(cred.uid)
}

/// The UID this daemon process itself is running as. Only connections from
/// this same UID are allowed — matches the filesystem permissions already
/// placed on the socket (0600, owner-only), but checked at the kernel level
/// rather than trusted from the filesystem alone.
pub fn own_uid() -> u32 {
    unsafe { libc::getuid() }
}
