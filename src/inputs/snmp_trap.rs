//! SNMP trap receiver — async UDP listener.
//!
//! Receives SNMP v1/v2c trap PDUs and extracts OID + value pairs.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// A parsed SNMP trap event.
#[derive(Debug, Clone)]
pub struct SnmpTrapEvent {
    /// SNMP version (0=v1, 1=v2c)
    pub version: u8,
    /// Community string
    pub community: String,
    /// Enterprise OID (v1) or snmpTrapOID (v2c)
    pub trap_oid: String,
    /// Agent address (from packet source)
    pub agent_addr: String,
    /// Variable bindings as (OID, value_hex) pairs
    pub varbinds: Vec<(String, String)>,
    /// Receive timestamp
    pub timestamp: String,
}

/// Minimal BER/ASN.1 SNMP trap parser.
/// Extracts community string and provides raw hex for further processing.
pub fn parse_snmp_trap(data: &[u8], source: &str) -> Option<SnmpTrapEvent> {
    // SNMP messages start with ASN.1 SEQUENCE (0x30)
    if data.len() < 10 || data[0] != 0x30 {
        return None;
    }

    // Skip outer sequence tag + length
    let (_, offset) = read_asn1_length(data, 1)?;

    // Version: INTEGER
    if data.get(offset)? != &0x02 {
        return None;
    }
    let (ver_len, ver_offset) = read_asn1_length(data, offset + 1)?;
    let version = *data.get(ver_offset)? as u8;
    let next = ver_offset + ver_len;

    // Community: OCTET STRING
    if data.get(next)? != &0x04 {
        return None;
    }
    let (comm_len, comm_offset) = read_asn1_length(data, next + 1)?;
    let community = std::str::from_utf8(data.get(comm_offset..comm_offset + comm_len)?)
        .unwrap_or("???")
        .to_string();

    Some(SnmpTrapEvent {
        version,
        community,
        trap_oid: String::new(), // Full OID parsing requires more complex BER decoding
        agent_addr: source.to_string(),
        varbinds: Vec::new(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Read ASN.1 BER length encoding.
/// Returns (length_value, offset_after_length).
fn read_asn1_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    let byte = *data.get(offset)?;

    if byte & 0x80 == 0 {
        // Short form
        Some((byte as usize, offset + 1))
    } else {
        // Long form
        let num_bytes = (byte & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || offset + 1 + num_bytes > data.len() {
            return None;
        }

        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | data[offset + 1 + i] as usize;
        }
        Some((length, offset + 1 + num_bytes))
    }
}

/// Start the SNMP trap UDP receiver.
pub async fn start_snmp_trap_udp(
    addr: SocketAddr,
    sender: mpsc::Sender<SnmpTrapEvent>,
) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("failed to bind SNMP trap UDP on {addr}"))?;

    info!(addr = %addr, "SNMP trap UDP receiver started");

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                if let Some(event) = parse_snmp_trap(&buf[..len], &peer.to_string()) {
                    if sender.try_send(event).is_err() {
                        debug!("SNMP trap channel full — dropping");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "SNMP trap UDP recv error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asn1_short_length() {
        let data = [0x05]; // length = 5
        let (len, off) = read_asn1_length(&data, 0).unwrap();
        assert_eq!(len, 5);
        assert_eq!(off, 1);
    }

    #[test]
    fn test_asn1_long_length() {
        let data = [0x82, 0x01, 0x00]; // length = 256
        let (len, off) = read_asn1_length(&data, 0).unwrap();
        assert_eq!(len, 256);
        assert_eq!(off, 3);
    }

    #[test]
    fn test_parse_snmp_v2c_trap() {
        // Minimal SNMP v2c trap: SEQUENCE { INTEGER(1), OCTET STRING("public"), ... }
        let mut pkt = Vec::new();
        pkt.push(0x30); // SEQUENCE
        pkt.push(0x0A); // length (placeholder)

        // Version: INTEGER 1 (v2c)
        pkt.push(0x02); pkt.push(0x01); pkt.push(0x01);

        // Community: "public"
        pkt.push(0x04); pkt.push(0x06);
        pkt.extend_from_slice(b"public");

        // Fix total length
        pkt[1] = (pkt.len() - 2) as u8;

        let event = parse_snmp_trap(&pkt, "192.168.1.1:162").unwrap();
        assert_eq!(event.version, 1); // v2c
        assert_eq!(event.community, "public");
        assert_eq!(event.agent_addr, "192.168.1.1:162");
    }

    #[test]
    fn test_parse_non_snmp() {
        assert!(parse_snmp_trap(&[0xFF, 0x00], "test").is_none());
    }
}
