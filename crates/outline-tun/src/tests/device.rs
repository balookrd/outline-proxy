//! Tests for the Android VpnService-fd attach path (`attach_preopened_fd`).

use super::*;

/// A pipe read-end stands in for the VpnService TUN fd — attach only dups it,
/// so any real fd exercises the path.
fn make_pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live 2-element array; `pipe` writes exactly two fds
    // into it and returns 0 on success, which we assert.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() must succeed");
    (fds[0], fds[1])
}

/// `attach_preopened_fd` dups the fd: the returned `File` owns an independent
/// copy, so dropping it must NOT close the caller's original, and offload is
/// always off on a preopened fd.
#[test]
fn attach_dups_and_leaves_original_open() {
    let (read_fd, write_fd) = make_pipe();

    let (file, gso) = attach_preopened_fd(read_fd).expect("attach must succeed");

    assert!(!gso.vnet_hdr, "vnet_hdr must be off on a preopened fd");
    assert!(!gso.tcp_gro, "tcp_gro must be off on a preopened fd");
    assert!(!gso.udp_gso, "udp_gso must be off on a preopened fd");

    // Drop our dup copy; the caller's original must survive.
    drop(file);

    // SAFETY: read-only `F_GETFD` on an fd we still own; no pointer args.
    // Returns >= 0 only while the fd is open.
    let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
    assert!(flags >= 0, "original fd must stay open after dropping the dup");

    // SAFETY: closing fds we own exactly once.
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}
