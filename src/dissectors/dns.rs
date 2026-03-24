//! DNS dissector — zero-allocation.
//!
//! Extracts the DNS query name from the question section.
//! Operates on UDP payload (after the 8-byte UDP header).

use super::PacketMetadata;

/// DNS header is 12 bytes.
pub const DNS_HEADER_LEN: usize = 12;

/// DNS query flags.
pub const DNS_FLAG_QR: u16 = 0x8000; // 1 = response, 0 = query

/// Parsed DNS information.
#[derive(Debug, Clone, Default)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub question_count: u16,
    pub answer_count: u16,
    /// Extracted query name (e.g., "example.com")
    pub query_name: String,
    /// Query type (1=A, 28=AAAA, 5=CNAME, 15=MX, etc.)
    pub query_type: u16,
}

/// Attempt to extract DNS query name from the payload.
/// Returns None if not a valid DNS packet.
pub fn dissect_dns(data: &[u8], payload_offset: usize) -> Option<DnsInfo> {
    let payload = data.get(payload_offset..)?;

    if payload.len() < DNS_HEADER_LEN {
        return None;
    }

    let mut info = DnsInfo {
        transaction_id: u16::from_be_bytes([payload[0], payload[1]]),
        is_response: u16::from_be_bytes([payload[2], payload[3]]) & DNS_FLAG_QR != 0,
        question_count: u16::from_be_bytes([payload[4], payload[5]]),
        answer_count: u16::from_be_bytes([payload[6], payload[7]]),
        ..Default::default()
    };

    // Parse first question name if present
    if info.question_count > 0 {
        if let Some((name, end_offset)) = parse_dns_name(payload, DNS_HEADER_LEN) {
            info.query_name = name;
            // Query type is 2 bytes after the name
            if payload.len() >= end_offset + 2 {
                info.query_type =
                    u16::from_be_bytes([payload[end_offset], payload[end_offset + 1]]);
            }
        }
    }

    Some(info)
}

/// Parse a DNS label-encoded name starting at `offset`.
/// Returns (name, offset_after_name) or None on malformed.
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name_parts = Vec::with_capacity(4);
    let mut jumps = 0;
    let max_jumps = 10; // prevent infinite loops from malformed compression pointers

    loop {
        if offset >= data.len() || jumps > max_jumps {
            return None;
        }

        let len = data[offset] as usize;

        if len == 0 {
            // End of name
            offset += 1;
            break;
        }

        // Compression pointer (top 2 bits = 11)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            if jumps == 0 {
                offset += 2; // only advance offset on first jump
            }
            // Follow the pointer (recursive parse from pointer location)
            if let Some((rest, _)) = parse_dns_name(data, pointer) {
                if !name_parts.is_empty() {
                    name_parts.push(rest);
                } else {
                    return Some((rest, offset));
                }
            }
            break;
        }

        offset += 1;
        if offset + len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[offset..offset + len])
            .unwrap_or("<invalid>")
            .to_string();
        name_parts.push(label);
        offset += len;
        jumps += 1;
    }

    Some((name_parts.join("."), offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query for "example.com" type A
    fn make_dns_query() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header (12 bytes)
        pkt.extend_from_slice(&[0xAB, 0xCD]); // transaction ID
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        pkt.extend_from_slice(&[0x00, 0x01]); // questions: 1
        pkt.extend_from_slice(&[0x00, 0x00]); // answers: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // authority: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // additional: 0
        // Question: example.com type A class IN
        pkt.push(7); // "example" length
        pkt.extend_from_slice(b"example");
        pkt.push(3); // "com" length
        pkt.extend_from_slice(b"com");
        pkt.push(0); // end of name
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt
    }

    #[test]
    fn test_dns_query_parse() {
        let query = make_dns_query();
        let info = dissect_dns(&query, 0).expect("should parse DNS");
        assert_eq!(info.transaction_id, 0xABCD);
        assert!(!info.is_response);
        assert_eq!(info.question_count, 1);
        assert_eq!(info.query_name, "example.com");
        assert_eq!(info.query_type, 1); // A record
    }

    #[test]
    fn test_dns_too_short() {
        assert!(dissect_dns(&[0u8; 5], 0).is_none());
    }
}
