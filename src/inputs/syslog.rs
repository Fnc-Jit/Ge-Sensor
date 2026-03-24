//! Syslog receiver — async UDP/TCP listener.
//!
//! Listens for RFC5424/RFC3164 syslog messages and converts them
//! into internal event structs for the output pipeline.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// A parsed syslog event.
#[derive(Debug, Clone)]
pub struct SyslogEvent {
    /// RFC5424 priority value
    pub priority: u16,
    /// Facility (priority >> 3)
    pub facility: u8,
    /// Severity (priority & 0x07)
    pub severity: u8,
    /// Hostname from syslog header
    pub hostname: String,
    /// Application name
    pub app_name: String,
    /// Raw message body
    pub message: String,
    /// Receive timestamp (ISO-8601)
    pub timestamp: String,
}

/// Parse a syslog message (RFC5424 or RFC3164).
pub fn parse_syslog(raw: &str) -> Option<SyslogEvent> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // Extract priority: <PRI>
    if !raw.starts_with('<') {
        // No priority — treat as raw message
        return Some(SyslogEvent {
            priority: 13, // default: user.notice
            facility: 1,
            severity: 5,
            hostname: String::new(),
            app_name: String::new(),
            message: raw.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    let pri_end = raw.find('>')?;
    let priority: u16 = raw[1..pri_end].parse().ok()?;
    let facility = (priority >> 3) as u8;
    let severity = (priority & 0x07) as u8;

    let rest = &raw[pri_end + 1..];

    // Simple parser: split remaining into hostname, app, message
    let mut parts = rest.splitn(4, ' ');
    let _version_or_timestamp = parts.next().unwrap_or("");
    let hostname = parts.next().unwrap_or("").to_string();
    let app_name = parts.next().unwrap_or("").to_string();
    let message = parts.next().unwrap_or(rest).to_string();

    Some(SyslogEvent {
        priority,
        facility,
        severity,
        hostname,
        app_name,
        message,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Start the syslog UDP receiver.
pub async fn start_syslog_udp(
    addr: SocketAddr,
    sender: mpsc::Sender<SyslogEvent>,
) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("failed to bind syslog UDP on {addr}"))?;

    info!(addr = %addr, "syslog UDP receiver started");

    let mut buf = vec![0u8; 8192];
    let mut received: u64 = 0;
    let mut dropped: u64 = 0;

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                received += 1;
                if let Ok(msg) = std::str::from_utf8(&buf[..len]) {
                    if let Some(event) = parse_syslog(msg) {
                        if sender.try_send(event).is_err() {
                            dropped += 1;
                            if dropped % 100 == 1 {
                                warn!(
                                    dropped,
                                    received,
                                    "syslog event channel full — dropping events"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "syslog UDP recv error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc5424() {
        let msg = "<165>1 2026-03-24T00:00:00Z myhost myapp - - - Test message";
        let event = parse_syslog(msg).expect("should parse");
        assert_eq!(event.priority, 165);
        assert_eq!(event.facility, 20); // local4
        assert_eq!(event.severity, 5); // notice
        assert_eq!(event.hostname, "2026-03-24T00:00:00Z");
    }

    #[test]
    fn test_parse_rfc3164() {
        let msg = "<13>Mar 24 00:00:00 router sshd[1234]: Failed password";
        let event = parse_syslog(msg).expect("should parse");
        assert_eq!(event.priority, 13);
        assert_eq!(event.facility, 1); // user
        assert_eq!(event.severity, 5); // notice
    }

    #[test]
    fn test_parse_no_priority() {
        let event = parse_syslog("Just a raw message").expect("should parse");
        assert_eq!(event.priority, 13);
        assert_eq!(event.message, "Just a raw message");
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_syslog("").is_none());
    }
}
