//! Optional local-network discovery.
//!
//! Discovery messages are deliberately unauthenticated but contain no secrets
//! and grant no authority. A worker must still be explicitly enrolled with a
//! short-lived pairing token and a pinned coordinator CA fingerprint.

#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const DISCOVERY_MAGIC: &str = "GETTER_DISCOVER_V1";
pub const DEFAULT_DISCOVERY_PORT: u16 = 47812;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryQuery {
    pub magic: String,
    pub protocol: String,
}

impl DiscoveryQuery {
    pub fn new() -> Self {
        Self {
            magic: DISCOVERY_MAGIC.to_owned(),
            protocol: crate::PROTOCOL_VERSION.to_owned(),
        }
    }
}

impl Default for DiscoveryQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryAnnouncement {
    pub magic: String,
    pub protocol: String,
    pub coordinator_name: String,
    pub coordinator_url: String,
    pub ca_fingerprint: Option<String>,
    pub version: String,
    pub announced_at: DateTime<Utc>,
}

impl DiscoveryAnnouncement {
    pub fn is_compatible(&self) -> bool {
        self.magic == DISCOVERY_MAGIC && self.protocol == crate::PROTOCOL_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_round_trips() {
        let announcement = DiscoveryAnnouncement {
            magic: DISCOVERY_MAGIC.into(),
            protocol: crate::PROTOCOL_VERSION.into(),
            coordinator_name: "lab".into(),
            coordinator_url: "https://192.0.2.4:47810".into(),
            ca_fingerprint: Some(format!("sha256:{}", "ab".repeat(32))),
            version: "0.1.0".into(),
            announced_at: Utc::now(),
        };
        let encoded = serde_json::to_vec(&announcement).expect("serialize");
        let decoded: DiscoveryAnnouncement = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, announcement);
        assert!(decoded.is_compatible());
    }

    #[test]
    fn unknown_discovery_fields_are_rejected() {
        let payload = br#"{"magic":"GETTER_DISCOVER_V1","protocol":"getter.protocol/v1","coordinator_name":"lab","coordinator_url":"https://127.0.0.1:47810","ca_fingerprint":"sha256:aa","version":"0.1.0","announced_at":"2026-01-01T00:00:00Z","admin_token":"oops"}"#;
        assert!(serde_json::from_slice::<DiscoveryAnnouncement>(payload).is_err());
    }
}
