//! DNP3 dissector.
//!
//! Parses DNP3 (Distributed Network Protocol 3) transport frames
//! on TCP/UDP port 20000.

/// DNP3 data link layer start bytes.
pub const DNP3_START_BYTES: [u8; 2] = [0x05, 0x64];

/// DNP3 function codes.
pub mod function_codes {
    pub const CONFIRM: u8 = 0x00;
    pub const READ: u8 = 0x01;
    pub const WRITE: u8 = 0x02;
    pub const DIRECT_OPERATE: u8 = 0x03;
    pub const DIRECT_OPERATE_NO_ACK: u8 = 0x04;
    pub const SELECT: u8 = 0x05;
    pub const OPERATE: u8 = 0x06;
    pub const COLD_RESTART: u8 = 0x0D;
    pub const WARM_RESTART: u8 = 0x0E;
    pub const DISABLE_UNSOLICITED: u8 = 0x15;
    pub const ENABLE_UNSOLICITED: u8 = 0x14;
    pub const RESPONSE: u8 = 0x81;
    pub const UNSOLICITED_RESPONSE: u8 = 0x82;
}

/// Parsed DNP3 frame.
#[derive(Debug, Clone)]
pub struct Dnp3Frame {
    /// Data link layer length
    pub length: u8,
    /// Control byte
    pub control: u8,
    /// Destination address
    pub destination: u16,
    /// Source address
    pub source: u16,
    /// Transport layer function code (if available)
    pub function_code: Option<u8>,
    /// Is this a control (write/operate) command?
    pub is_control_command: bool,
}

/// Minimum DNP3 data link header: start(2) + length(1) + control(1) + dst(2) + src(2) + CRC(2)
pub const DNP3_DL_HEADER_LEN: usize = 10;

/// Parse a DNP3 frame from the given payload.
pub fn dissect_dnp3(data: &[u8], payload_offset: usize) -> Option<Dnp3Frame> {
    let payload = data.get(payload_offset..)?;

    if payload.len() < DNP3_DL_HEADER_LEN {
        return None;
    }

    // Check start bytes
    if payload[0] != DNP3_START_BYTES[0] || payload[1] != DNP3_START_BYTES[1] {
        return None;
    }

    let length = payload[2];
    let control = payload[3];
    let destination = u16::from_le_bytes([payload[4], payload[5]]);
    let source = u16::from_le_bytes([payload[6], payload[7]]);

    // Try to extract function code from transport/application layer
    // DNP3 has transport header (1 byte) then application header with function code
    let function_code = if payload.len() > DNP3_DL_HEADER_LEN + 1 {
        // Skip CRC(2) + transport header(1), function code follows
        let app_offset = DNP3_DL_HEADER_LEN + 1;
        if payload.len() > app_offset {
            Some(payload[app_offset])
        } else {
            None
        }
    } else {
        None
    };

    let is_control_command = function_code.map_or(false, |fc| {
        matches!(
            fc,
            function_codes::WRITE
                | function_codes::DIRECT_OPERATE
                | function_codes::DIRECT_OPERATE_NO_ACK
                | function_codes::SELECT
                | function_codes::OPERATE
                | function_codes::COLD_RESTART
                | function_codes::WARM_RESTART
        )
    });

    Some(Dnp3Frame {
        length,
        control,
        destination,
        source,
        function_code,
        is_control_command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnp3_read_request() {
        let mut data = vec![0u8; 15];
        data[0] = 0x05; data[1] = 0x64; // start bytes
        data[2] = 0x08;                   // length
        data[3] = 0xC0;                   // control
        data[4] = 0x01; data[5] = 0x00;   // dst = 1
        data[6] = 0x03; data[7] = 0x00;   // src = 3
        // CRC (placeholder)
        data[8] = 0x00; data[9] = 0x00;
        // Transport + app header
        data[10] = 0xC0;                  // transport header
        data[11] = function_codes::READ;  // function code = READ

        let frame = dissect_dnp3(&data, 0).expect("should parse");
        assert_eq!(frame.destination, 1);
        assert_eq!(frame.source, 3);
        assert_eq!(frame.function_code, Some(function_codes::READ));
        assert!(!frame.is_control_command);
    }

    #[test]
    fn test_dnp3_operate_detection() {
        let mut data = vec![0u8; 15];
        data[0] = 0x05; data[1] = 0x64;
        data[2] = 0x08;
        data[3] = 0xC0;
        data[4] = 0x01; data[5] = 0x00;
        data[6] = 0x03; data[7] = 0x00;
        data[8] = 0x00; data[9] = 0x00;
        data[10] = 0xC0;
        data[11] = function_codes::DIRECT_OPERATE;

        let frame = dissect_dnp3(&data, 0).expect("should parse");
        assert!(frame.is_control_command, "DIRECT_OPERATE should be flagged as control");
    }

    #[test]
    fn test_dnp3_bad_start_bytes() {
        let data = vec![0xFF, 0xFF, 0x08, 0xC0, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert!(dissect_dnp3(&data, 0).is_none());
    }
}
