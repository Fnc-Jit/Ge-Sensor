//! Ring buffer for PCAP storage.
//!
//! A fixed-capacity circular buffer that stores raw packet data.
//! When full, oldest entries are overwritten. On alert trigger,
//! the buffer is frozen and flushed to a PCAP file.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing::{debug, info};

/// Entry in the ring buffer.
#[derive(Clone)]
struct RingEntry {
    /// Timestamp seconds since epoch
    ts_sec: u32,
    /// Timestamp microseconds
    ts_usec: u32,
    /// Captured length
    cap_len: u32,
    /// Original length on wire
    orig_len: u32,
    /// Raw packet data
    data: Vec<u8>,
}

/// Circular packet ring buffer.
pub struct PacketRingBuffer {
    entries: Vec<RingEntry>,
    capacity: usize,
    write_pos: usize,
    count: usize,
    total_bytes: usize,
    max_bytes: usize,
}

impl PacketRingBuffer {
    /// Create a new ring buffer with the given byte capacity.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            entries: Vec::with_capacity(1024),
            capacity: 0, // unlimited entries, bounded by bytes
            write_pos: 0,
            count: 0,
            total_bytes: 0,
            max_bytes,
        }
    }

    /// Push a packet into the ring buffer.
    pub fn push(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) {
        let entry_size = data.len() + 16; // pcap record header

        // Evict oldest entries if we'd exceed max_bytes
        while self.total_bytes + entry_size > self.max_bytes && self.count > 0 {
            let oldest_idx = if self.write_pos >= self.count {
                self.write_pos - self.count
            } else {
                self.entries.len() - (self.count - self.write_pos)
            };
            let evicted_size = self.entries[oldest_idx].data.len() + 16;
            self.total_bytes = self.total_bytes.saturating_sub(evicted_size);
            self.count -= 1;
        }

        let entry = RingEntry {
            ts_sec,
            ts_usec,
            cap_len: data.len() as u32,
            orig_len: data.len() as u32,
            data: data.to_vec(),
        };

        if self.write_pos < self.entries.len() {
            self.entries[self.write_pos] = entry;
        } else {
            self.entries.push(entry);
        }

        self.total_bytes += entry_size;
        self.count = (self.count + 1).min(self.entries.len());
        self.write_pos = (self.write_pos + 1) % self.entries.capacity().max(self.entries.len() + 1);
    }

    /// Flush the ring buffer contents to a PCAP file.
    pub fn flush_to_pcap(&self, path: &Path) -> Result<usize> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(path)
            .with_context(|| format!("failed to create PCAP file: {}", path.display()))?;

        // PCAP global header (24 bytes)
        let pcap_header: [u8; 24] = [
            0xD4, 0xC3, 0xB2, 0xA1, // magic number
            0x02, 0x00, 0x04, 0x00, // version 2.4
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0xFF, 0xFF, 0x00, 0x00, // snaplen = 65535
            0x01, 0x00, 0x00, 0x00, // network = LINKTYPE_ETHERNET
        ];
        file.write_all(&pcap_header)?;

        let mut packets_written = 0;

        // Write entries in order
        let start = if self.count < self.entries.len() {
            0
        } else {
            self.write_pos
        };

        for i in 0..self.count.min(self.entries.len()) {
            let idx = (start + i) % self.entries.len();
            let entry = &self.entries[idx];

            // PCAP record header (16 bytes)
            file.write_all(&entry.ts_sec.to_le_bytes())?;
            file.write_all(&entry.ts_usec.to_le_bytes())?;
            file.write_all(&entry.cap_len.to_le_bytes())?;
            file.write_all(&entry.orig_len.to_le_bytes())?;
            file.write_all(&entry.data)?;

            packets_written += 1;
        }

        info!(
            path = %path.display(),
            packets = packets_written,
            "PCAP file written"
        );

        Ok(packets_written)
    }

    /// Current number of packets in the buffer.
    pub fn len(&self) -> usize {
        self.count.min(self.entries.len())
    }

    /// Current byte usage.
    pub fn bytes_used(&self) -> usize {
        self.total_bytes
    }

    /// Is the buffer empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ring_buffer_push_and_flush() {
        let mut ring = PacketRingBuffer::new(10_000);

        // Push 5 packets
        for i in 0..5u32 {
            let data = vec![0xAA; 100];
            ring.push(1711238400 + i, i * 1000, &data);
        }

        assert_eq!(ring.len(), 5);
        assert!(ring.bytes_used() > 0);

        // Flush to PCAP
        let dir = tempdir().unwrap();
        let pcap_path = dir.path().join("test.pcap");
        let written = ring.flush_to_pcap(&pcap_path).expect("should write PCAP");
        assert_eq!(written, 5);

        // Verify PCAP file has correct magic number
        let content = fs::read(&pcap_path).unwrap();
        assert_eq!(&content[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        // 24 header + 5 * (16 record_header + 100 data) = 24 + 580 = 604
        assert_eq!(content.len(), 604);
    }

    #[test]
    fn test_ring_buffer_eviction() {
        // Small buffer: 500 bytes max
        let mut ring = PacketRingBuffer::new(500);

        // Push packets until eviction triggers
        for i in 0..20u32 {
            let data = vec![i as u8; 50]; // 50 bytes + 16 header = 66 bytes each
            ring.push(i, 0, &data);
        }

        // Should have evicted old entries, staying under 500 bytes
        assert!(ring.bytes_used() <= 500);
        assert!(ring.len() < 20);
    }

    #[test]
    fn test_empty_ring_buffer() {
        let ring = PacketRingBuffer::new(1000);
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);

        let dir = tempdir().unwrap();
        let pcap_path = dir.path().join("empty.pcap");
        let written = ring.flush_to_pcap(&pcap_path).expect("should write");
        assert_eq!(written, 0);
    }
}
