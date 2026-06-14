#![allow(dead_code)]
//! Runs the real `outline-ss-rust` server binary as a subprocess, mirroring
//! `proxy_test_utils::ProxyProcess` (which runs the client). `kill()` is the
//! "connection refused" fault used by the inter-uplink failover tests: drop one
//! server and its endpoint stops answering while siblings stay up.

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

type BoxError = Box<dyn std::error::Error>;

/// Cargo does not export `CARGO_BIN_EXE_*` for a *different* workspace member,
/// so locate the server binary next to the running test binary
/// (`target/<profile>/outline-ss-rust`) and build it once on first use. The
/// build is a fast no-op when already up to date.
fn server_binary_path() -> Result<PathBuf, BoxError> {
    static BUILT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let mut dir = std::env::current_exe().map_err(|e| e.to_string())?;
            dir.pop(); // drop the test binary file name
            if dir.ends_with("deps") {
                dir.pop(); // deps/ → target/<profile>/
            }
            let bin = dir.join(format!("outline-ss-rust{}", std::env::consts::EXE_SUFFIX));

            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let mut cmd = Command::new(cargo);
            cmd.args(["build", "-p", "outline-ss-rust"]);
            if dir.components().any(|c| c.as_os_str() == "release") {
                cmd.arg("--release");
            }
            let status = cmd.status().map_err(|e| format!("spawn cargo build: {e}"))?;
            if !status.success() {
                return Err("`cargo build -p outline-ss-rust` failed".to_string());
            }
            Ok(bin)
        })
        .clone()
        .map_err(Into::into)
}

pub struct ServerProcess {
    child: Child,
    log_path: PathBuf,
    listen: SocketAddr,
}

impl ServerProcess {
    /// Spawn the server with `--config <config_path>`, logging to `log_path`.
    /// `listen` is the server's `[server].listen` address, used by `wait_ready`.
    pub fn start(
        config_path: &Path,
        log_path: &Path,
        listen: SocketAddr,
    ) -> Result<Self, BoxError> {
        let binary = server_binary_path()?;
        let stdout = fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let stderr = fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let child = Command::new(binary)
            .arg("--config")
            .arg(config_path)
            // Surface session-resumption / orphan-park debug lines so failover
            // diagnostics are visible in the captured server log.
            .env("RUST_LOG", "info,outline_ss_rust=debug")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        Ok(Self {
            child,
            log_path: log_path.to_path_buf(),
            listen,
        })
    }

    /// Poll the TCP listener until it accepts a connection or the deadline
    /// passes; fail early with logs if the process exits.
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<(), BoxError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if TcpStream::connect(self.listen).is_ok() {
                return Ok(());
            }
            if self.child.try_wait()?.is_some() {
                return Err(format!("server exited early:\n{}", self.logs()?).into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(
            format!("timed out waiting for server on {}.\nlogs:\n{}", self.listen, self.logs()?)
                .into(),
        )
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub fn logs(&self) -> Result<String, BoxError> {
        Ok(fs::read_to_string(&self.log_path).unwrap_or_default())
    }

    /// Append a marker line to the log so multi-phase test output is readable.
    pub fn log_marker(&self, marker: &str) {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&self.log_path) {
            let _ = writeln!(f, "==== {marker} ====");
        }
    }

    /// Kill the server — the "downed uplink" fault for inter-uplink failover.
    pub fn kill(&mut self) -> Result<(), BoxError> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
            let _ = self.child.wait()?;
        }
        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
