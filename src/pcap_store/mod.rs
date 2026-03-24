//! Selective PCAP ring buffer for ge-sensor.
//!
//! Provides alert-triggered PCAP storage with a fixed-size ring buffer.
//! When an alert fires, the ring buffer is frozen and flushed to a PCAP file.
//!
//! Design:
//! - Pre-allocated ring buffer of configurable size (default 512 MB)
//! - Older packets are overwritten when buffer is full (ring behavior)
//! - On alert trigger, the buffer snapshot is written as a PCAP file

pub mod ring_buffer;

use std::path::PathBuf;

/// PCAP store configuration.
#[derive(Debug, Clone)]
pub struct PcapStoreConfig {
    /// Base directory for saved PCAP files
    pub output_dir: PathBuf,
    /// Ring buffer capacity in bytes
    pub ring_buffer_bytes: usize,
    /// Maximum number of saved PCAP files to retain
    pub max_files: usize,
    /// Trigger mode: "alert", "always", "off"
    pub trigger: PcapTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapTrigger {
    Alert,
    Always,
    Off,
}

impl Default for PcapStoreConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("/var/lib/ge-sensor/pcap"),
            ring_buffer_bytes: 512 * 1024 * 1024, // 512 MB
            max_files: 100,
            trigger: PcapTrigger::Alert,
        }
    }
}
