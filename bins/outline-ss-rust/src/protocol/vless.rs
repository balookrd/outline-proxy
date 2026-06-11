//! VLESS protocol layer: wire codec re-exported from `outline-wire`, plus
//! the server's account entity ([`VlessUser`]) that binds a parsed UUID to
//! the human-readable config label and per-user fwmark.

use std::sync::Arc;

#[cfg(test)]
pub use outline_wire::vless::{
    ADDON_TAG_RESUME_CAPABLE, ADDON_TAG_RESUME_ID, ADDON_TAG_RESUME_RESULT, ADDON_TAG_SESSION_ID,
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP,
};
pub use outline_wire::vless::{
    AddonResumeResult, VERSION, VlessCommand, VlessError, VlessRequest, encode_response_addons,
    mask_uuid, parse_request, parse_uuid,
};

#[derive(Debug, Clone)]
pub struct VlessUser {
    id: [u8; 16],
    label: Arc<str>,
    fwmark: Option<u32>,
}

impl VlessUser {
    /// Build a VLESS user from its UUID and the human-readable account
    /// label coming from `config.users[].id` (e.g. `alice-mom`,
    /// `aeza`). The label is what surfaces in `user="..."` Prometheus
    /// labels — using the masked UUID instead pollutes the dashboard's
    /// `User` template variable with two parallel namespaces (raw IDs
    /// for SS, masked UUIDs for VLESS) that can't be cross-referenced.
    pub fn new(id: String, label: Arc<str>, fwmark: Option<u32>) -> Result<Self, VlessError> {
        let parsed = parse_uuid(&id)?;
        Ok(Self { id: parsed, label, fwmark })
    }

    pub const fn id_bytes(&self) -> &[u8; 16] {
        &self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn label_arc(&self) -> Arc<str> {
        Arc::clone(&self.label)
    }

    pub const fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }
}

pub fn find_user<'a>(users: &'a [VlessUser], user_id: &[u8; 16]) -> Option<&'a VlessUser> {
    users.iter().find(|user| user.id_bytes() == user_id)
}

#[cfg(test)]
#[path = "tests/vless.rs"]
mod tests;
