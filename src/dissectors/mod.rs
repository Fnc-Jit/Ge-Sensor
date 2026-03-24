//! Protocol dissector registry for ge-sensor.
//!
//! Zero-allocation packet dissection using slice indexing.
//! All metadata structs store offsets into the original `&[u8]` packet
//! rather than copying data, achieving O(1) memory overhead per packet.

pub mod tcp;
pub mod udp;
pub mod icmp;
pub mod dns;
pub mod http;
pub mod tls;
pub mod ot;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ethernet header constants.
pub const ETH_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// IP protocol numbers.
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMPV6: u8 = 58;

/// Complete packet metadata extracted by the dissector pipeline.
/// Zero-allocation: stores parsed values, not copies of raw bytes.
#[derive(Debug, Clone, Default)]
pub struct PacketMetadata {
    // ── Layer 2 ──
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,

    // ── Layer 3 ──
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ip_proto: u8,
    pub ip_ttl: u8,
    pub ip_total_len: u16,

    // ── Layer 4 ──
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub tcp_window: u16,
    pub tcp_seq: u32,
    pub tcp_ack: u32,

    // ── ICMP ──
    pub icmp_type: u8,
    pub icmp_code: u8,

    // ── Payload ──
    /// Offset into the packet where L4 payload begins
    pub payload_offset: usize,
    /// Length of the L4 payload
    pub payload_len: usize,

    // ── Protocol identification ──
    pub protocol_name: &'static str,
}

/// TCP flag bit constants.
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// Dissect a raw Ethernet frame into structured metadata.
///
/// Returns `None` if the packet is too short or malformed.
/// This is the main entry point — it handles Ethernet → IP → TCP/UDP/ICMP.
pub fn dissect_packet(data: &[u8]) -> Option<PacketMetadata> {
    if data.len() < ETH_HEADER_LEN {
        return None;
    }

    let mut meta = PacketMetadata::default();

    // ── Ethernet header ──
    meta.dst_mac.copy_from_slice(&data[0..6]);
    meta.src_mac.copy_from_slice(&data[6..12]);
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = ETH_HEADER_LEN;

    // ── VLAN tag handling (802.1Q) ──
    if ethertype == ETHERTYPE_VLAN {
        if data.len() < offset + 4 {
            return None;
        }
        meta.vlan_id = Some(u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x0FFF);
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }
    meta.ethertype = ethertype;

    // ── Layer 3: IP ──
    match ethertype {
        ETHERTYPE_IPV4 => {
            if let Some(ip_offset) = dissect_ipv4(data, offset, &mut meta) {
                offset = ip_offset;
            } else {
                return Some(meta);
            }
        }
        ETHERTYPE_IPV6 => {
            if let Some(ip_offset) = dissect_ipv6(data, offset, &mut meta) {
                offset = ip_offset;
            } else {
                return Some(meta);
            }
        }
        _ => {
            meta.protocol_name = "other";
            return Some(meta);
        }
    }

    // ── Layer 4: TCP / UDP / ICMP ──
    match meta.ip_proto {
        IP_PROTO_TCP => {
            tcp::dissect_tcp(data, offset, &mut meta);
        }
        IP_PROTO_UDP => {
            udp::dissect_udp(data, offset, &mut meta);
        }
        IP_PROTO_ICMP | IP_PROTO_ICMPV6 => {
            icmp::dissect_icmp(data, offset, &mut meta);
        }
        _ => {
            meta.protocol_name = "ip_other";
            meta.payload_offset = offset;
            meta.payload_len = data.len().saturating_sub(offset);
        }
    }

    // ── Layer 7: Protocol identification by port + payload heuristics ──
    // Use port-based detection first, then optionally refine with payload.
    // This ensures protocols are tagged even on ACK-only or encrypted packets.
    if meta.ip_proto == IP_PROTO_TCP {
        let s = meta.src_port;
        let d = meta.dst_port;

        if s == 443 || d == 443 || s == 8443 || d == 8443 {
            meta.protocol_name = "tls";
            // Try to extract SNI from ClientHello if payload present
            if meta.payload_len > 0 {
                let _ = tls::dissect_tls(data, meta.payload_offset);
            }
        } else if s == 80 || d == 80 || s == 8080 || d == 8080 || s == 8000 || d == 8000
                || s == 9090 || d == 9090 || s == 3000 || d == 3000
                || s == 3128 || d == 3128 || s == 8888 || d == 8888 {
            meta.protocol_name = "http";
        } else if s == 53 || d == 53 {
            meta.protocol_name = "dns";
        } else if meta.payload_len > 4 {
            // Heuristic: try to detect HTTP on non-standard ports
            if let Some(_) = http::dissect_http(data, meta.payload_offset) {
                meta.protocol_name = "http";
            }
        }
    } else if meta.ip_proto == IP_PROTO_UDP {
        let s = meta.src_port;
        let d = meta.dst_port;

        if s == 53 || d == 53 || s == 5353 || d == 5353 {
            meta.protocol_name = "dns";
        } else if s == 123 || d == 123 {
            meta.protocol_name = "ntp";
        } else if s == 67 || d == 67 || s == 68 || d == 68 {
            meta.protocol_name = "dhcp";
        } else if s == 443 || d == 443 {
            meta.protocol_name = "quic";
        }
    }

    Some(meta)
}

/// Parse an IPv4 header. Returns the offset to the L4 payload, or None on malformed.
fn dissect_ipv4(data: &[u8], offset: usize, meta: &mut PacketMetadata) -> Option<usize> {
    if data.len() < offset + 20 {
        return None;
    }

    let version_ihl = data[offset];
    let ihl = (version_ihl & 0x0F) as usize * 4;

    if ihl < 20 || data.len() < offset + ihl {
        return None;
    }

    meta.ip_total_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    meta.ip_ttl = data[offset + 8];
    meta.ip_proto = data[offset + 9];

    let src = Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    );
    let dst = Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    );
    meta.src_ip = Some(IpAddr::V4(src));
    meta.dst_ip = Some(IpAddr::V4(dst));

    Some(offset + ihl)
}

/// Parse an IPv6 header. Returns the offset to the L4 payload, or None on malformed.
fn dissect_ipv6(data: &[u8], offset: usize, meta: &mut PacketMetadata) -> Option<usize> {
    if data.len() < offset + 40 {
        return None;
    }

    meta.ip_ttl = data[offset + 7]; // hop limit
    meta.ip_proto = data[offset + 6]; // next header
    meta.ip_total_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[offset + 8..offset + 24]);
    dst_bytes.copy_from_slice(&data[offset + 24..offset + 40]);

    meta.src_ip = Some(IpAddr::V6(Ipv6Addr::from(src_bytes)));
    meta.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)));

    Some(offset + 40)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Craft a minimal IPv4 TCP SYN packet for testing.
    fn make_ipv4_tcp_syn() -> Vec<u8> {
        let mut pkt = vec![0u8; 54]; // 14 eth + 20 ip + 20 tcp

        // Ethernet
        pkt[12] = 0x08;
        pkt[13] = 0x00; // IPv4

        // IPv4
        pkt[14] = 0x45; // version=4, IHL=5
        pkt[16] = 0x00;
        pkt[17] = 40; // total_len = 40
        pkt[22] = 64; // TTL
        pkt[23] = IP_PROTO_TCP; // protocol
        // src: 192.168.1.100
        pkt[26] = 192;
        pkt[27] = 168;
        pkt[28] = 1;
        pkt[29] = 100;
        // dst: 10.0.0.1
        pkt[30] = 10;
        pkt[31] = 0;
        pkt[32] = 0;
        pkt[33] = 1;

        // TCP
        pkt[34] = 0xC0; pkt[35] = 0x00; // src port = 49152
        pkt[36] = 0x00; pkt[37] = 0x50; // dst port = 80
        // seq
        pkt[38] = 0x00; pkt[39] = 0x00; pkt[40] = 0x00; pkt[41] = 0x01;
        // ack
        pkt[42] = 0x00; pkt[43] = 0x00; pkt[44] = 0x00; pkt[45] = 0x00;
        // data offset = 5 (20 bytes), flags = SYN
        pkt[46] = 0x50; // data offset = 5 << 4
        pkt[47] = tcp_flags::SYN;
        // window
        pkt[48] = 0xFF; pkt[49] = 0xFF;

        pkt
    }

    #[test]
    fn test_dissect_ipv4_tcp_syn() {
        let pkt = make_ipv4_tcp_syn();
        let meta = dissect_packet(&pkt).expect("should parse");

        assert_eq!(meta.ethertype, ETHERTYPE_IPV4);
        assert_eq!(
            meta.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
        assert_eq!(
            meta.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(meta.ip_proto, IP_PROTO_TCP);
        assert_eq!(meta.ip_ttl, 64);
        assert_eq!(meta.src_port, 49152);
        assert_eq!(meta.dst_port, 80);
        assert_eq!(meta.tcp_flags, tcp_flags::SYN);
        assert_eq!(meta.tcp_seq, 1);
        assert_eq!(meta.tcp_window, 0xFFFF);
        assert_eq!(meta.protocol_name, "http");
    }

    #[test]
    fn test_dissect_too_short() {
        assert!(dissect_packet(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_dissect_vlan() {
        let mut pkt = vec![0u8; 58]; // 14 eth + 4 vlan + 20 ip + 20 tcp

        // Ethernet with VLAN tag
        pkt[12] = 0x81;
        pkt[13] = 0x00; // VLAN ethertype
        pkt[14] = 0x00;
        pkt[15] = 0x64; // VLAN ID = 100
        pkt[16] = 0x08;
        pkt[17] = 0x00; // inner ethertype = IPv4

        // IPv4 at offset 18
        pkt[18] = 0x45;
        pkt[20] = 0x00;
        pkt[21] = 40;
        pkt[26] = 64; // TTL
        pkt[27] = IP_PROTO_UDP;
        // src: 10.10.10.1
        pkt[30] = 10; pkt[31] = 10; pkt[32] = 10; pkt[33] = 1;
        // dst: 10.10.10.2
        pkt[34] = 10; pkt[35] = 10; pkt[36] = 10; pkt[37] = 2;

        // UDP at offset 38
        pkt[38] = 0x00; pkt[39] = 53; // src port = 53
        pkt[40] = 0x10; pkt[41] = 0x00; // dst port = 4096
        pkt[42] = 0x00; pkt[43] = 8; // length = 8 (header only)

        let meta = dissect_packet(&pkt).expect("should parse VLAN");
        assert_eq!(meta.vlan_id, Some(100));
        assert_eq!(meta.ethertype, ETHERTYPE_IPV4);
        assert_eq!(meta.ip_proto, IP_PROTO_UDP);
        assert_eq!(meta.src_port, 53);
        assert_eq!(meta.protocol_name, "dns");
    }
}
