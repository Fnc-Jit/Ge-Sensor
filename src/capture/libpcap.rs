//! Libpcap capture provider for ge-sensor.
//!
//! Cross-platform packet capture using the `pcap` crate (wraps libpcap).
//! This is the default/fallback capture backend and works on Linux, macOS, and Windows.

use anyhow::{Context, Result};
use pcap::{Active, Capture, Device};
use tracing::{debug, info};

use super::{CaptureConfig, CaptureProvider, CaptureStats, CapturedPacket, PacketInfo};

/// Libpcap-based capture provider.
pub struct LibpcapProvider {
    capture: Capture<Active>,
    interface: String,
}

impl LibpcapProvider {
    /// Create a new libpcap capture on the specified interface.
    pub fn new(config: CaptureConfig) -> Result<Self> {
        info!(
            interface = %config.interface,
            promisc = config.promisc,
            snap_len = config.snap_len,
            "initializing libpcap capture"
        );

        // Find the device — use "any" or "lo0" for loopback testing
        let capture = Capture::from_device(config.interface.as_str())
            .with_context(|| {
                format!(
                    "failed to open capture device '{}' — is it available?",
                    config.interface
                )
            })?
            .promisc(config.promisc)
            .snaplen(config.snap_len as i32)
            .timeout(config.timeout.as_millis() as i32)
            .immediate_mode(true)
            .open()
            .with_context(|| {
                format!(
                    "failed to activate libpcap on '{}' — may need root/sudo",
                    config.interface
                )
            })?;

        info!(
            interface = %config.interface,
            datalink = ?capture.get_datalink(),
            "libpcap capture active"
        );

        Ok(Self {
            capture,
            interface: config.interface,
        })
    }
}

impl CaptureProvider for LibpcapProvider {
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>> {
        match self.capture.next_packet() {
            Ok(packet) => {
                let info = PacketInfo {
                    timestamp_us: packet.header.ts.tv_sec as u64 * 1_000_000
                        + packet.header.ts.tv_usec as u64,
                    orig_len: packet.header.len,
                    cap_len: packet.header.caplen,
                };

                Ok(Some(CapturedPacket {
                    info,
                    data: packet.data.to_vec(),
                }))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("libpcap capture error: {}", e)),
        }
    }

    fn backend_name(&self) -> &'static str {
        "libpcap"
    }

    fn interface(&self) -> &str {
        &self.interface
    }

    fn stats(&mut self) -> Result<CaptureStats> {
        let stats = self
            .capture
            .stats()
            .context("failed to get libpcap stats")?;
        Ok(CaptureStats {
            received: stats.received as u64,
            dropped: stats.dropped as u64,
            if_dropped: stats.if_dropped as u64,
        })
    }
}
