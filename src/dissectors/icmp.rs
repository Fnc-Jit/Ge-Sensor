//! ICMP header dissector — zero-allocation.
//!
//! Extracts type and code from ICMP/ICMPv6 headers.

use super::PacketMetadata;

/// ICMP header minimum size.
pub const ICMP_HEADER_LEN: usize = 8;

/// Parse ICMP header at offset. Populates meta with type and code.
pub fn dissect_icmp(data: &[u8], offset: usize, meta: &mut PacketMetadata) {
    if data.len() < offset + 4 {
        meta.protocol_name = "icmp_truncated";
        return;
    }

    meta.icmp_type = data[offset];
    meta.icmp_code = data[offset + 1];
    meta.protocol_name = if meta.ip_proto == super::IP_PROTO_ICMPV6 {
        "icmpv6"
    } else {
        "icmp"
    };

    // Payload after ICMP header (type-dependent, at least 4 bytes header)
    let payload_start = offset + ICMP_HEADER_LEN.min(data.len() - offset);
    meta.payload_offset = payload_start;
    meta.payload_len = data.len().saturating_sub(payload_start);
}

/// Common ICMP type constants.
pub mod icmp_types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_echo_request() {
        let mut data = vec![0u8; 12]; // 8 header + 4 payload
        data[0] = icmp_types::ECHO_REQUEST; // type
        data[1] = 0; // code

        let mut meta = super::super::PacketMetadata::default();
        meta.ip_proto = super::super::IP_PROTO_ICMP;
        dissect_icmp(&data, 0, &mut meta);

        assert_eq!(meta.icmp_type, icmp_types::ECHO_REQUEST);
        assert_eq!(meta.icmp_code, 0);
        assert_eq!(meta.protocol_name, "icmp");
    }
}
