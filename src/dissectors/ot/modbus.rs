//! Modbus/TCP dissector.
//!
//! Parses the Modbus Application Protocol (MBAP) header and function code
//! from TCP payload on port 502.

/// Modbus function codes.
pub mod function_codes {
    pub const READ_COILS: u8 = 0x01;
    pub const READ_DISCRETE_INPUTS: u8 = 0x02;
    pub const READ_HOLDING_REGISTERS: u8 = 0x03;
    pub const READ_INPUT_REGISTERS: u8 = 0x04;
    pub const WRITE_SINGLE_COIL: u8 = 0x05;
    pub const WRITE_SINGLE_REGISTER: u8 = 0x06;
    pub const WRITE_MULTIPLE_COILS: u8 = 0x0F;
    pub const WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
    pub const DIAGNOSTICS: u8 = 0x08;
    pub const ENCAP_INTERFACE_TRANSPORT: u8 = 0x2B;
}

/// Parsed Modbus/TCP frame.
#[derive(Debug, Clone)]
pub struct ModbusFrame {
    /// Transaction identifier
    pub transaction_id: u16,
    /// Protocol identifier (0x0000 for Modbus)
    pub protocol_id: u16,
    /// Length of remaining data
    pub length: u16,
    /// Unit identifier (slave address)
    pub unit_id: u8,
    /// Function code
    pub function_code: u8,
    /// Is this an exception response? (function code bit 7 set)
    pub is_exception: bool,
    /// Exception code (if is_exception)
    pub exception_code: u8,
    /// Is this a write operation?
    pub is_write: bool,
}

/// MBAP header is 7 bytes: transaction(2) + protocol(2) + length(2) + unit(1)
pub const MBAP_HEADER_LEN: usize = 7;

/// Parse a Modbus/TCP frame from the given payload.
pub fn dissect_modbus(data: &[u8], payload_offset: usize) -> Option<ModbusFrame> {
    let payload = data.get(payload_offset..)?;

    if payload.len() < MBAP_HEADER_LEN + 1 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]);
    let unit_id = payload[6];
    let function_code = payload[7];

    // Protocol ID must be 0x0000 for Modbus
    if protocol_id != 0x0000 {
        return None;
    }

    let is_exception = function_code & 0x80 != 0;
    let actual_fc = function_code & 0x7F;

    let exception_code = if is_exception && payload.len() > 8 {
        payload[8]
    } else {
        0
    };

    let is_write = matches!(
        actual_fc,
        function_codes::WRITE_SINGLE_COIL
            | function_codes::WRITE_SINGLE_REGISTER
            | function_codes::WRITE_MULTIPLE_COILS
            | function_codes::WRITE_MULTIPLE_REGISTERS
    );

    Some(ModbusFrame {
        transaction_id,
        protocol_id,
        length,
        unit_id,
        function_code: actual_fc,
        is_exception,
        exception_code,
        is_write,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_read_holding_registers() {
        // MBAP header + function code 0x03 (read holding registers)
        let data: Vec<u8> = vec![
            0x00, 0x01, // transaction ID = 1
            0x00, 0x00, // protocol ID = 0 (Modbus)
            0x00, 0x06, // length = 6
            0x01,       // unit ID = 1
            0x03,       // function code = read holding registers
            0x00, 0x00, // starting address = 0
            0x00, 0x0A, // quantity = 10
        ];

        let frame = dissect_modbus(&data, 0).expect("should parse");
        assert_eq!(frame.transaction_id, 1);
        assert_eq!(frame.function_code, function_codes::READ_HOLDING_REGISTERS);
        assert!(!frame.is_exception);
        assert!(!frame.is_write);
        assert_eq!(frame.unit_id, 1);
    }

    #[test]
    fn test_modbus_write_detection() {
        let data: Vec<u8> = vec![
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01,
            0x10, // write multiple registers
            0x00, 0x00, 0x00, 0x02,
        ];

        let frame = dissect_modbus(&data, 0).expect("should parse");
        assert!(frame.is_write, "write multiple registers should be flagged");
    }

    #[test]
    fn test_modbus_exception() {
        let data: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01,
            0x83, // exception for function 0x03
            0x02, // exception code: illegal data address
        ];

        let frame = dissect_modbus(&data, 0).expect("should parse");
        assert!(frame.is_exception);
        assert_eq!(frame.function_code, 0x03);
        assert_eq!(frame.exception_code, 0x02);
    }

    #[test]
    fn test_non_modbus_protocol_id() {
        let data: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x01, // protocol ID = 1 (not Modbus)
            0x00, 0x06, 0x01, 0x03,
        ];
        assert!(dissect_modbus(&data, 0).is_none());
    }
}
