//! Capture interface abstraction for ge-sensor.
//!
//! Defines the `CaptureProvider` trait for zero-copy packet access and
//! provides a factory function to select the appropriate backend based
//! on configuration (libpcap, AF_PACKET, AF_XDP).

pub mod libpcap;

use anyhow::Result;
use std::time::Duration;

/// Metadata about a captured packet.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Timestamp of capture (microseconds since epoch)
    pub timestamp_us: u64,
    /// Original packet length on wire
    pub orig_len: u32,
    /// Captured length (may be less than orig_len due to snap_len)
    pub cap_len: u32,
}

/// A captured packet: metadata + raw bytes.
#[derive(Debug)]
pub struct CapturedPacket {
    pub info: PacketInfo,
    /// Raw packet bytes (owned for now; AF_PACKET will use zero-copy slices)
    pub data: Vec<u8>,
}

/// Trait for packet capture backends.
///
/// Each implementation (libpcap, AF_PACKET, AF_XDP) must provide:
/// - Initialization with interface name and capture parameters
/// - Blocking packet retrieval
/// - Graceful shutdown
pub trait CaptureProvider: Send {
    /// Retrieve the next packet. Blocks until a packet is available
    /// or the timeout expires (returns Ok(None) on timeout).
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>>;

    /// Get capture backend name for metrics/logging.
    fn backend_name(&self) -> &'static str;

    /// Get the interface being captured.
    fn interface(&self) -> &str;

    /// Get capture statistics (packets received/dropped by kernel).
    fn stats(&mut self) -> Result<CaptureStats>;
}

/// Capture statistics from the kernel/driver.
#[derive(Debug, Default, Clone)]
pub struct CaptureStats {
    /// Packets received by the capture backend
    pub received: u64,
    /// Packets dropped by the kernel
    pub dropped: u64,
    /// Packets dropped by the interface (driver)
    pub if_dropped: u64,
}

/// Configuration for creating a capture provider.
pub struct CaptureConfig {
    pub interface: String,
    pub promisc: bool,
    pub snap_len: u32,
    pub timeout: Duration,
}

/// Factory: create the appropriate capture backend based on mode.
pub fn create_provider(
    mode: &crate::config::CaptureMode,
    config: CaptureConfig,
) -> Result<Box<dyn CaptureProvider>> {
    use crate::config::CaptureMode;

    match mode {
        CaptureMode::Libpcap => {
            let provider = libpcap::LibpcapProvider::new(config)?;
            Ok(Box::new(provider))
        }
        CaptureMode::AfPacket => {
            #[cfg(target_os = "linux")]
            {
                // Will be implemented in TASK-004
                anyhow::bail!("AF_PACKET not yet implemented (TASK-004)");
            }
            #[cfg(not(target_os = "linux"))]
            {
                tracing::warn!("AF_PACKET only available on Linux — falling back to libpcap");
                let provider = libpcap::LibpcapProvider::new(config)?;
                Ok(Box::new(provider))
            }
        }
        CaptureMode::AfXdp => {
            #[cfg(target_os = "linux")]
            {
                // Will be implemented in TASK-005
                anyhow::bail!("AF_XDP not yet implemented (TASK-005)");
            }
            #[cfg(not(target_os = "linux"))]
            {
                tracing::warn!("AF_XDP only available on Linux — falling back to libpcap");
                let provider = libpcap::LibpcapProvider::new(config)?;
                Ok(Box::new(provider))
            }
        }
    }
}
