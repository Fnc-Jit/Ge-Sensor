//! TCP header dissector — zero-allocation.
//!
//! Extracts source/destination ports, sequence/ack numbers, flags, and window size
//! from a TCP header at the given offset within the packet buffer.

use super::PacketMetadata;

/// Parse TCP header at offset. Populates meta with ports, flags, seq/ack, window.
pub fn dissect_tcp(data: &[u8], offset: usize, meta: &mut PacketMetadata) {
    // Minimum TCP header is 20 bytes
    if data.len() < offset + 20 {
        meta.protocol_name = "tcp_truncated";
        return;
    }

    meta.src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    meta.dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    meta.tcp_seq = u32::from_be_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    meta.tcp_ack = u32::from_be_bytes([
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
        data[offset + 11],
    ]);

    // Data offset is upper 4 bits of byte 12, in 32-bit words
    let data_offset = ((data[offset + 12] >> 4) as usize) * 4;
    meta.tcp_flags = data[offset + 13];
    meta.tcp_window = u16::from_be_bytes([data[offset + 14], data[offset + 15]]);
    meta.protocol_name = "tcp";

    // Payload starts after TCP header
    let payload_start = offset + data_offset.max(20);
    meta.payload_offset = payload_start;
    meta.payload_len = data.len().saturating_sub(payload_start);
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn test_tcp_flags_all() {
        // Verify flag constants
        assert_eq!(tcp_flags::FIN, 0x01);
        assert_eq!(tcp_flags::SYN, 0x02);
        assert_eq!(tcp_flags::RST, 0x04);
        assert_eq!(tcp_flags::PSH, 0x08);
        assert_eq!(tcp_flags::ACK, 0x10);
        assert_eq!(tcp_flags::URG, 0x20);
        assert_eq!(tcp_flags::SYN | tcp_flags::ACK, 0x12);
    }

    #[test]
    fn test_xmas_tree_detection() {
        // XMAS scan = FIN + PSH + URG
        let flags = tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG;
        assert_eq!(flags, 0x29);
        assert!(flags & tcp_flags::FIN != 0);
        assert!(flags & tcp_flags::PSH != 0);
        assert!(flags & tcp_flags::URG != 0);
        assert!(flags & tcp_flags::SYN == 0);
    }
}
