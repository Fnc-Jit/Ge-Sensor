//! Output pipeline for ge-sensor.
//!
//! Handles delivery of normalized events to:
//! - Kafka (primary) via rdkafka
//! - RocksDB DLQ (fallback on Kafka failure)

pub mod kafka;
pub mod dlq;

use anyhow::Result;
use serde::Serialize;
use std::net::IpAddr;

/// God's Eye Event Schema (GES) — the normalized event format sent to Kafka.
/// Matches the GES spec exactly with mandatory fields.
#[derive(Debug, Clone, Serialize)]
pub struct GesEvent {
    /// ISO-8601 UTC timestamp
    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    /// Tenant UUID for multi-tenant isolation
    #[serde(rename = "tenant.id")]
    pub tenant_id: String,

    /// Event classification: alert, event, metric, state, signal
    #[serde(rename = "event.kind")]
    pub event_kind: String,

    /// Event categories: network, authentication, intrusion_detection, etc.
    #[serde(rename = "event.category")]
    pub event_category: Vec<String>,

    /// Network protocol: tcp, udp, icmp, dns, http, tls, modbus, dnp3
    #[serde(rename = "network.protocol")]
    pub network_protocol: String,

    /// Source IP address
    #[serde(rename = "source.ip")]
    pub source_ip: String,

    /// Source port
    #[serde(rename = "source.port")]
    pub source_port: u16,

    /// Destination IP address
    #[serde(rename = "destination.ip")]
    pub destination_ip: String,

    /// Destination port
    #[serde(rename = "destination.port")]
    pub destination_port: u16,

    /// God's Eye behavioral trust score (0-100)
    #[serde(rename = "ge.trust_score")]
    pub trust_score: f32,

    /// God's Eye ensemble risk score (0-100)
    #[serde(rename = "ge.risk_score")]
    pub risk_score: f32,

    /// Original unparsed log/packet data (preserved for forensics)
    #[serde(rename = "ge.raw")]
    pub raw: String,

    /// SHA-256 Merkle chain integrity hash
    pub merkle_hash: String,

    /// 14-element ML feature array
    #[serde(rename = "ml_features")]
    pub ml_features: Option<[f32; 14]>,
}

impl GesEvent {
    /// Create a GES event from packet dissection metadata.
    pub fn from_packet(
        protocol: &str,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        tenant_id: &str,
        ml_features: Option<[f32; 14]>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tenant_id: tenant_id.to_string(),
            event_kind: "event".to_string(),
            event_category: vec!["network".to_string()],
            network_protocol: protocol.to_string(),
            source_ip: src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            source_port: src_port,
            destination_ip: dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            destination_port: dst_port,
            trust_score: 100.0,
            risk_score: 0.0,
            raw: String::new(),
            merkle_hash: String::new(),
            ml_features,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ges_event_serialization() {
        let event = GesEvent::from_packet(
            "tcp",
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            12345,
            80,
            "00000000-0000-0000-0000-000000000001",
            None,
        );

        let json = serde_json::to_string(&event).expect("should serialize");
        assert!(json.contains("\"@timestamp\""));
        assert!(json.contains("\"tenant.id\""));
        assert!(json.contains("\"event.kind\":\"event\""));
        assert!(json.contains("\"network.protocol\":\"tcp\""));
        assert!(json.contains("\"source.ip\":\"192.168.1.1\""));
        assert!(json.contains("\"source.port\":12345"));
        assert!(json.contains("\"ge.trust_score\":100.0"));
        assert!(json.contains("\"ge.risk_score\":0.0"));
    }
}
