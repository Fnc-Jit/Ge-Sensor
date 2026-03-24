//! UDP header dissector — zero-allocation.
//!
//! Extracts source/destination ports and length from a UDP header.

use super::PacketMetadata;

/// UDP header is always exactly 8 bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Parse UDP header at offset. Populates meta with ports and payload info.
pub fn dissect_udp(data: &[u8], offset: usize, meta: &mut PacketMetadata) {
    if data.len() < offset + UDP_HEADER_LEN {
        meta.protocol_name = "udp_truncated";
        return;
    }

    meta.src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    meta.dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

    let udp_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
    meta.protocol_name = "udp";

    // Payload starts after 8-byte UDP header
    let payload_start = offset + UDP_HEADER_LEN;
    meta.payload_offset = payload_start;
    // Use actual remaining data, capped by declared UDP length
    let max_payload = udp_len.saturating_sub(UDP_HEADER_LEN);
    meta.payload_len = max_payload.min(data.len().saturating_sub(payload_start));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_parse() {
        // Minimal UDP header: src=1234, dst=53, len=12, checksum=0, then 4 bytes payload
        let mut data = vec![0u8; 20]; // offset 0 + 8 header + 4 payload
        data[0] = 0x04; data[1] = 0xD2; // port 1234
        data[2] = 0x00; data[3] = 0x35; // port 53
        data[4] = 0x00; data[5] = 12;   // length = 12 (8 hdr + 4 payload)
        data[6] = 0x00; data[7] = 0x00; // checksum
        data[8] = b'T'; data[9] = b'E'; data[10] = b'S'; data[11] = b'T';

        let mut meta = super::super::PacketMetadata::default();
        dissect_udp(&data, 0, &mut meta);

        assert_eq!(meta.src_port, 1234);
        assert_eq!(meta.dst_port, 53);
        assert_eq!(meta.protocol_name, "udp");
        assert_eq!(meta.payload_offset, 8);
        assert_eq!(meta.payload_len, 4);
    }
}
