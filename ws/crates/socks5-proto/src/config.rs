#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5AuthUserConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5AuthConfig {
    pub users: Vec<Socks5AuthUserConfig>,
}
