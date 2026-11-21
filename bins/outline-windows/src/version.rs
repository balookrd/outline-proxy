use serde::{Deserialize, Serialize};

/// Version and build metadata of the desktop application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppVersionInfo {
    pub version: String,
    pub commit: String,
    pub channel: String,
    pub display_string: String,
}

pub struct AppVersion;

impl AppVersion {
    pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    pub const COMMIT: &'static str = match option_env!("OUTLINE_BUILD_COMMIT") {
        Some(c) => c,
        None => "dev",
    };
    pub const CHANNEL: &'static str = match option_env!("OUTLINE_BUILD_CHANNEL") {
        Some(ch) => ch,
        None => "nightly",
    };

    /// Returns current application build metadata.
    pub fn current() -> AppVersionInfo {
        let version = Self::VERSION.to_string();
        let commit = Self::COMMIT.to_string();
        let channel = Self::CHANNEL.to_string();
        let display_string = Self::format_display(&channel, &version, &commit);

        AppVersionInfo { version, commit, channel, display_string }
    }

    /// Checks if a remote/published commit matches current commit (prefix matching and dirty handling).
    pub fn same_commit(published: &str, current: &str) -> bool {
        let a = published.trim().to_ascii_lowercase().replace("-dirty", "");
        let b = current.trim().to_ascii_lowercase().replace("-dirty", "");
        if a.len() < 7 || b.len() < 7 {
            return false;
        }
        a.starts_with(&b) || b.starts_with(&a)
    }

    /// Formats version string for UI display.
    /// - Nightly / dev: "nightly · v1.9.2 (971282b6)"
    /// - Official release: "v1.9.2"
    pub fn format_display(channel: &str, version: &str, commit: &str) -> String {
        let clean_version = version.strip_prefix('v').unwrap_or(version).trim();
        let channel = channel.trim();
        let commit = commit.trim();

        if channel == "release"
            && (commit.is_empty() || commit == "1" || commit == clean_version || commit == "dev")
        {
            return format!("v{clean_version}");
        }

        let mut res = String::new();
        if !channel.is_empty() && channel != "release" {
            res.push_str(channel);
            res.push_str(" · ");
        }
        res.push('v');
        res.push_str(clean_version);

        if !commit.is_empty() && commit != "1" && commit != clean_version {
            res.push_str(" (");
            res.push_str(commit);
            res.push(')');
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_string_nightly() {
        let display = AppVersion::format_display("nightly", "1.9.2", "971282b6");
        assert_eq!(display, "nightly · v1.9.2 (971282b6)");

        let release_display = AppVersion::format_display("release", "1.9.2", "");
        assert_eq!(release_display, "v1.9.2");
    }

    #[test]
    fn test_same_commit_exact_and_prefix() {
        assert!(AppVersion::same_commit("971282b6", "971282b6"));
        assert!(AppVersion::same_commit("971282b61234567890abcdef1234567890abcdef", "971282b6"));
        assert!(AppVersion::same_commit("971282b6", "971282b61234567890abcdef1234567890abcdef"));
        assert!(!AppVersion::same_commit("971282b6", "12345678"));
        // Short commits (< 7 chars) are not valid
        assert!(!AppVersion::same_commit("123456", "123456"));
        assert!(!AppVersion::same_commit("1", "1"));
        assert!(!AppVersion::same_commit("dev", "dev"));
    }

    #[test]
    fn test_same_commit_dirty_handling() {
        assert!(AppVersion::same_commit("971282b6", "971282b6-dirty"));
        assert!(AppVersion::same_commit("971282b6-dirty", "971282b6"));
        assert!(AppVersion::same_commit(
            "971282b61234567890abcdef1234567890abcdef",
            "971282b6-dirty"
        ));
        assert!(!AppVersion::same_commit("123456-dirty", "123456"));
    }

    #[test]
    fn test_current_version_info() {
        let current = AppVersion::current();
        assert_eq!(current.version, "1.9.2");
        assert!(!current.commit.is_empty());
        assert!(!current.channel.is_empty());
        assert!(!current.display_string.is_empty());
    }
}
