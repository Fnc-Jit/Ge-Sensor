//! TLS dissector — SNI extraction from ClientHello.
//!
//! Extracts the Server Name Indication (SNI) from TLS ClientHello messages
//! without any heap allocation for the common case.

/// Parsed TLS information.
#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    /// TLS content type (22 = handshake)
    pub content_type: u8,
    /// TLS version (major, minor)
    pub version: (u8, u8),
    /// Handshake type (1 = ClientHello)
    pub handshake_type: u8,
    /// Server Name Indication string
    pub sni: String,
}

/// TLS content type for Handshake
const TLS_HANDSHAKE: u8 = 22;
/// TLS handshake type for ClientHello
const TLS_CLIENT_HELLO: u8 = 1;
/// Extension type for SNI
const EXT_SNI: u16 = 0;

/// Attempt to extract TLS SNI from a ClientHello in the payload.
pub fn dissect_tls(data: &[u8], payload_offset: usize) -> Option<TlsInfo> {
    let payload = data.get(payload_offset..)?;

    // TLS record header: 1 content_type + 2 version + 2 length = 5 bytes
    if payload.len() < 5 {
        return None;
    }

    let content_type = payload[0];
    if content_type != TLS_HANDSHAKE {
        return None;
    }

    let version = (payload[1], payload[2]);
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Handshake header: 1 type + 3 length = 4 bytes
    if payload.len() < 5 + 4 {
        return None;
    }

    let handshake_type = payload[5];
    if handshake_type != TLS_CLIENT_HELLO {
        return Some(TlsInfo {
            content_type,
            version,
            handshake_type,
            sni: String::new(),
        });
    }

    // ClientHello structure:
    // offset 5: handshake type (1)
    // offset 6-8: handshake length (3)
    // offset 9-10: client version (2)
    // offset 11-42: random (32)
    // offset 43: session_id_len (1)
    let mut offset = 9; // start of ClientHello body
    let max_offset = (5 + record_len).min(payload.len());

    // Skip version + random
    offset += 2 + 32; // version (2) + random (32) = 34

    if offset >= max_offset {
        return None;
    }

    // Skip session ID
    let session_id_len = payload[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > max_offset {
        return None;
    }

    // Skip cipher suites
    let cipher_suites_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if offset + 1 > max_offset {
        return None;
    }

    // Skip compression methods
    let compression_len = payload[offset] as usize;
    offset += 1 + compression_len;

    if offset + 2 > max_offset {
        return None;
    }

    // Extensions length
    let extensions_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset += 2;
    let extensions_end = (offset + extensions_len).min(max_offset);

    // Walk extensions looking for SNI (type 0)
    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;

        if ext_type == EXT_SNI && ext_len > 5 && offset + ext_len <= extensions_end {
            // SNI extension:
            // 2 bytes: server name list length
            // 1 byte: name type (0 = hostname)
            // 2 bytes: name length
            // N bytes: hostname
            let name_type = payload[offset + 2];
            if name_type == 0 {
                let name_len =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
                if offset + 5 + name_len <= extensions_end {
                    let sni = std::str::from_utf8(&payload[offset + 5..offset + 5 + name_len])
                        .unwrap_or("")
                        .to_string();
                    return Some(TlsInfo {
                        content_type,
                        version,
                        handshake_type,
                        sni,
                    });
                }
            }
        }

        offset += ext_len;
    }

    Some(TlsInfo {
        content_type,
        version,
        handshake_type,
        sni: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with SNI "test.gods-eye.io"
    fn make_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_ext_len = 5 + sni_bytes.len(); // 2 list_len + 1 type + 2 name_len + name
        let extensions_len = 4 + sni_ext_len; // 2 ext_type + 2 ext_len + payload

        let session_id_len: u8 = 0;
        let cipher_suites: &[u8] = &[0x00, 0x02, 0x00, 0x2F]; // 1 cipher suite
        let compression: &[u8] = &[0x01, 0x00]; // 1 compression method (null)

        let hello_body_len = 2 + 32 + 1 + session_id_len as usize
            + cipher_suites.len()
            + compression.len()
            + 2
            + extensions_len;

        let mut pkt = Vec::new();

        // TLS record header
        pkt.push(TLS_HANDSHAKE); // content type
        pkt.extend_from_slice(&[0x03, 0x01]); // version TLS 1.0
        let record_len = (4 + hello_body_len) as u16; // handshake header + body
        pkt.extend_from_slice(&record_len.to_be_bytes());

        // Handshake header
        pkt.push(TLS_CLIENT_HELLO);
        let hs_len = hello_body_len as u32;
        pkt.push((hs_len >> 16) as u8);
        pkt.push((hs_len >> 8) as u8);
        pkt.push(hs_len as u8);

        // ClientHello body
        pkt.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(session_id_len); // session ID length
        pkt.extend_from_slice(cipher_suites);
        pkt.extend_from_slice(compression);

        // Extensions
        pkt.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // SNI extension
        pkt.extend_from_slice(&EXT_SNI.to_be_bytes()); // type = 0
        pkt.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // ext length
        let list_len = (3 + sni_bytes.len()) as u16;
        pkt.extend_from_slice(&list_len.to_be_bytes()); // server name list length
        pkt.push(0); // name type = hostname
        pkt.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(sni_bytes);

        pkt
    }

    #[test]
    fn test_tls_sni_extraction() {
        let hello = make_client_hello_with_sni("test.gods-eye.io");
        let info = dissect_tls(&hello, 0).expect("should parse TLS");
        assert_eq!(info.content_type, TLS_HANDSHAKE);
        assert_eq!(info.handshake_type, TLS_CLIENT_HELLO);
        assert_eq!(info.sni, "test.gods-eye.io");
    }

    #[test]
    fn test_tls_non_handshake() {
        // Not a handshake record
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(dissect_tls(&data, 0).is_none());
    }

    #[test]
    fn test_tls_too_short() {
        assert!(dissect_tls(&[0x16, 0x03], 0).is_none());
    }
}
