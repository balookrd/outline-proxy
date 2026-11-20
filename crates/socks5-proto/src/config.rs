#[derive(Clone, PartialEq, Eq)]
pub struct Socks5AuthUserConfig {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Socks5AuthUserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5AuthUserConfig")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5AuthConfig {
    pub users: Vec<Socks5AuthUserConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_auth_user_config_debug_redacts_password() {
        let user = Socks5AuthUserConfig {
            username: "alice".to_string(),
            password: "super_secret_password".to_string(),
        };
        let debug = format!("{user:?}");
        assert!(debug.contains("alice"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_password"));
    }
}
