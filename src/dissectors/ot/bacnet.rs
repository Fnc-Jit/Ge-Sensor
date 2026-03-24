//! BACnet dissector.
//!
//! Parses BACnet/IP (Building Automation and Control Network)
//! on UDP port 47808 (0xBAC0).

/// BACnet/IP virtual link control (BVLC) types.
pub mod bvlc_types {
    pub const RESULT: u8 = 0x00;
    pub const ORIGINAL_UNICAST: u8 = 0x0A;
    pub const ORIGINAL_BROADCAST: u8 = 0x0B;
    pub const FORWARDED_NPDU: u8 = 0x04;
    pub const REGISTER_FD: u8 = 0x05;
}

/// BACnet service choices (confirmed).
pub mod service_choices {
    pub const READ_PROPERTY: u8 = 12;
    pub const WRITE_PROPERTY: u8 = 15;
    pub const SUBSCRIBE_COV: u8 = 5;
    pub const CONFIRMED_COV_NOTIFICATION: u8 = 1;
    pub const I_AM: u8 = 0;      // unconfirmed
    pub const WHO_IS: u8 = 8;    // unconfirmed
}

/// Parsed BACnet/IP frame.
#[derive(Debug, Clone)]
pub struct BacnetFrame {
    /// BVLC type
    pub bvlc_type: u8,
    /// BVLC function
    pub bvlc_function: u8,
    /// BVLC packet length
    pub bvlc_length: u16,
    /// NPDU version
    pub npdu_version: Option<u8>,
    /// Is this a confirmed request?
    pub is_confirmed: bool,
    /// Service choice (if available)
    pub service_choice: Option<u8>,
    /// Is this a write/control operation?
    pub is_write: bool,
}

/// BACnet/IP BVLC header is 4 bytes: type(1) + function(1) + length(2)
pub const BVLC_HEADER_LEN: usize = 4;

/// Parse a BACnet/IP frame from the given payload.
pub fn dissect_bacnet(data: &[u8], payload_offset: usize) -> Option<BacnetFrame> {
    let payload = data.get(payload_offset..)?;

    if payload.len() < BVLC_HEADER_LEN {
        return None;
    }

    let bvlc_type = payload[0];
    let bvlc_function = payload[1];
    let bvlc_length = u16::from_be_bytes([payload[2], payload[3]]);

    // BVLC type must be 0x81 for BACnet/IP
    if bvlc_type != 0x81 {
        return None;
    }

    let mut frame = BacnetFrame {
        bvlc_type,
        bvlc_function,
        bvlc_length,
        npdu_version: None,
        is_confirmed: false,
        service_choice: None,
        is_write: false,
    };

    // NPDU starts after BVLC header
    if payload.len() > BVLC_HEADER_LEN {
        frame.npdu_version = Some(payload[BVLC_HEADER_LEN]);

        // Try to extract APDU info
        // NPDU: version(1) + control(1) [+ optional fields]
        if payload.len() > BVLC_HEADER_LEN + 2 {
            let npdu_control = payload[BVLC_HEADER_LEN + 1];
            let has_dst = npdu_control & 0x20 != 0;
            let has_src = npdu_control & 0x08 != 0;

            // Calculate APDU offset (skip NPDU routing fields)
            let mut apdu_offset = BVLC_HEADER_LEN + 2;
            if has_dst {
                if payload.len() > apdu_offset + 3 {
                    let dst_len = payload[apdu_offset + 2] as usize;
                    apdu_offset += 3 + dst_len;
                }
            }
            if has_src {
                if payload.len() > apdu_offset + 3 {
                    let src_len = payload[apdu_offset + 2] as usize;
                    apdu_offset += 3 + src_len;
                }
            }
            if has_dst {
                apdu_offset += 1; // hop count
            }

            // APDU type byte
            if payload.len() > apdu_offset {
                let apdu_type = (payload[apdu_offset] >> 4) & 0x0F;
                frame.is_confirmed = apdu_type == 0; // confirmed request

                if frame.is_confirmed && payload.len() > apdu_offset + 3 {
                    frame.service_choice = Some(payload[apdu_offset + 3]);
                    frame.is_write = frame.service_choice == Some(service_choices::WRITE_PROPERTY);
                }
            }
        }
    }

    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bacnet_bvlc_parse() {
        // Minimal BACnet/IP BVLC header + NPDU
        let data: Vec<u8> = vec![
            0x81,       // BVLC type = BACnet/IP
            0x0A,       // function = original unicast
            0x00, 0x0C, // length = 12
            0x01,       // NPDU version = 1
            0x04,       // NPDU control (expecting reply)
            // APDU: confirmed request
            0x00,       // APDU type = confirmed request (0 << 4)
            0x05,       // max segments / max resp
            0x01,       // invoke ID
            service_choices::READ_PROPERTY,
        ];

        let frame = dissect_bacnet(&data, 0).expect("should parse");
        assert_eq!(frame.bvlc_type, 0x81);
        assert_eq!(frame.bvlc_function, bvlc_types::ORIGINAL_UNICAST);
        assert_eq!(frame.npdu_version, Some(1));
    }

    #[test]
    fn test_bacnet_bad_type() {
        let data = vec![0x82, 0x0A, 0x00, 0x04];
        assert!(dissect_bacnet(&data, 0).is_none());
    }

    #[test]
    fn test_bacnet_too_short() {
        assert!(dissect_bacnet(&[0x81, 0x0A], 0).is_none());
    }
}
