//! Optional local-network discovery over UDP broadcast.
//!
//! Advertisements contain only the coordinator URL, human-readable name,
//! protocol/version, and CA fingerprint. There is no token, admin secret, or
//! automatic trust. Discovery can be disabled without affecting operation.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use chrono::Utc;
use getter_core::config::DiscoveryConfig;
use getter_protocol::{DiscoveryAnnouncement, DiscoveryQuery, DISCOVERY_MAGIC};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const MAX_DATAGRAM: usize = 8192;

pub fn spawn_announcer(
    config: DiscoveryConfig,
    coordinator_name: String,
    coordinator_url: String,
    ca_fingerprint: Option<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) =
            announce_loop(config, coordinator_name, coordinator_url, ca_fingerprint).await
        {
            warn!(error = %error, "discovery announcer stopped");
        }
    })
}

async fn announce_loop(
    config: DiscoveryConfig,
    coordinator_name: String,
    coordinator_url: String,
    ca_fingerprint: Option<String>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    let target = config
        .target
        .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::BROADCAST, config.port)));
    let announcement = DiscoveryAnnouncement {
        magic: DISCOVERY_MAGIC.to_owned(),
        protocol: getter_protocol::PROTOCOL_VERSION.to_owned(),
        coordinator_name,
        coordinator_url,
        ca_fingerprint,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        announced_at: Utc::now(),
    };
    let payload = serde_json::to_vec(&announcement)?;
    if payload.len() > MAX_DATAGRAM {
        anyhow::bail!("discovery announcement is too large");
    }
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut announcement = announcement.clone();
        announcement.announced_at = Utc::now();
        let payload = serde_json::to_vec(&announcement)?;
        match socket.send_to(&payload, target).await {
            Ok(_) => debug!(target = %target, "sent discovery advertisement"),
            Err(error) => {
                warn!(target = %target, error = %error, "could not send discovery advertisement")
            }
        }
    }
}

/// Send a discovery query and collect compatible announcements for `duration`.
/// The local port must be free; this command must not run on the coordinator
/// process itself if it has bound the discovery port for listening (the
/// coordinator only uses an ephemeral sending socket, so that is not the case).
pub async fn discover(port: u16, duration: Duration) -> anyhow::Result<Vec<DiscoveryAnnouncement>> {
    if duration.is_zero() || duration > Duration::from_secs(30) {
        anyhow::bail!("discovery duration must be between 1 and 30 seconds");
    }
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .map_err(|error| anyhow::anyhow!("could not bind discovery port {port}: {error}"))?;
    socket.set_broadcast(true)?;
    let query = serde_json::to_vec(&DiscoveryQuery::new())?;
    let broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, port));
    // Send twice; UDP is lossy and one extra datagram is harmless and stateless.
    let _ = socket.send_to(&query, broadcast).await;
    let _ = socket.send_to(&query, broadcast).await;

    let deadline = tokio::time::Instant::now() + duration;
    let mut announcements = Vec::new();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, source))) => {
                let payload = &buffer[..length];
                match serde_json::from_slice::<DiscoveryAnnouncement>(payload) {
                    Ok(announcement) if announcement.is_compatible() => {
                        if !announcements
                            .iter()
                            .any(|existing: &DiscoveryAnnouncement| {
                                existing.coordinator_url == announcement.coordinator_url
                            })
                        {
                            debug!(source = %source, url = %announcement.coordinator_url, "discovered coordinator");
                            announcements.push(announcement);
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        debug!(source = %source, error = %error, "ignored malformed discovery datagram");
                    }
                }
            }
            Ok(Err(error)) => {
                debug!(error = %error, "discovery receive failed");
                break;
            }
            Err(_) => break,
        }
    }
    Ok(announcements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn broadcaster_sends_valid_announcement_to_configured_target() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let target = receiver.local_addr().expect("addr");
        let task = spawn_announcer(
            DiscoveryConfig {
                enabled: true,
                port: target.port(),
                interval_secs: 1,
                target: Some(target),
            },
            "test coordinator".into(),
            "https://127.0.0.1:47810".into(),
            Some(format!("sha256:{}", "a".repeat(64))),
        );
        let mut buf = vec![0; MAX_DATAGRAM];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(3), receiver.recv_from(&mut buf))
                .await
                .expect("timeout")
                .expect("receive");
        let announcement: DiscoveryAnnouncement =
            serde_json::from_slice(&buf[..length]).expect("json");
        assert!(announcement.is_compatible());
        assert_eq!(announcement.coordinator_name, "test coordinator");
        assert_eq!(announcement.coordinator_url, "https://127.0.0.1:47810");
        task.abort();
    }
}
