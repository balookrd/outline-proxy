//! VLESS protocol layer: wire codec re-exported from `outline-wire`, plus
//! the server's account entity ([`VlessUser`]) that binds a parsed UUID to
//! the human-readable config label and per-user fwmark.

use std::net::IpAddr;
use std::sync::Arc;

use outline_net::IpAliasTable;

#[cfg(test)]
pub use outline_wire::vless::{COMMAND_MUX, COMMAND_TCP, COMMAND_UDP};
pub use outline_wire::vless::{
    VERSION, VlessCommand, VlessError, VlessRequest, mask_uuid, parse_request, parse_uuid,
};

#[derive(Debug, Clone)]
pub struct VlessUser {
    id: [u8; 16],
    label: Arc<str>,
    fwmark: Option<u32>,
    /// Source-IP → alias table for accounting relabeling (metrics/NAT/logs).
    /// `None` for the common case of no aliases. See [`Self::effective_label`].
    aliases: Option<Arc<IpAliasTable>>,
}

impl VlessUser {
    /// Build a VLESS user from its UUID and the human-readable account
    /// label coming from `config.users[].id` (e.g. `alice-mom`,
    /// `aeza`). The label is what surfaces in `user="..."` Prometheus
    /// labels — using the masked UUID instead pollutes the dashboard's
    /// `User` template variable with two parallel namespaces (raw IDs
    /// for SS, masked UUIDs for VLESS) that can't be cross-referenced.
    pub fn new(
        id: String,
        label: Arc<str>,
        fwmark: Option<u32>,
        aliases: Option<Arc<IpAliasTable>>,
    ) -> Result<Self, VlessError> {
        let parsed = parse_uuid(&id)?;
        Ok(Self { id: parsed, label, fwmark, aliases })
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

    /// Effective accounting label for a client whose source IP is `peer`: the
    /// matching alias when `peer` falls into one of this user's configured
    /// subnets, otherwise the base config label. A `None` peer or no match
    /// falls back to the base label. Accounting only — never authentication.
    pub fn effective_label(&self, peer: Option<IpAddr>) -> Arc<str> {
        peer.and_then(|ip| self.aliases.as_ref().and_then(|t| t.resolve(ip)))
            .unwrap_or_else(|| self.label_arc())
    }

    /// Clone with `label` replaced by the effective accounting label for
    /// `peer`, so every downstream consumer that reads `label`/`label_arc` is
    /// transparently relabeled without further plumbing. Cheap: a couple of
    /// `Arc` bumps and one `Arc<str>` swap.
    pub fn with_effective_label(self, peer: Option<IpAddr>) -> Self {
        let label = self.effective_label(peer);
        Self { label, ..self }
    }
}

pub fn find_user<'a>(users: &'a [VlessUser], user_id: &[u8; 16]) -> Option<&'a VlessUser> {
    users.iter().find(|user| user.id_bytes() == user_id)
}

#[cfg(test)]
#[path = "tests/vless.rs"]
mod tests;
