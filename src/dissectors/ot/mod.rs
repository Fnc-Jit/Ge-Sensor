//! OT/SCADA protocol dissectors for ge-sensor.
//!
//! Dissectors for industrial control system protocols:
//! - Modbus/TCP (port 502)
//! - DNP3 (port 20000)
//! - BACnet (port 47808/0xBAC0)

pub mod modbus;
pub mod dnp3;
pub mod bacnet;
