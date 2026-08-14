//! `RunOptions` default: a plain `run` must not carry a preopened TUN fd.

use crate::RunOptions;

#[test]
fn default_run_options_have_no_tun_fd() {
    assert_eq!(RunOptions::default().tun_fd, None);
}
