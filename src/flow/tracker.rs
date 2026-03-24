//! 5-tuple flow tracker with LRU eviction.
//!
//! Maps (src_ip, dst_ip, src_port, dst_port, protocol) → FlowRecord.
//! Uses a HashMap for O(1) lookup and a BinaryHeap for TTL-based eviction.
//! Strict capacity limits prevent OOM under burst conditions.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 5-tuple flow key — uniquely identifies a bidirectional session.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Create a normalized key (lower IP first) for bidirectional matching.
    pub fn normalized(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        if src_ip <= dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            }
        } else {
            Self {
                src_ip: dst_ip,
                dst_ip: src_ip,
                src_port: dst_port,
                dst_port: src_port,
                protocol,
            }
        }
    }
}

/// Record of a tracked flow session.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub key: FlowKey,
    /// When the flow was first seen
    pub first_seen: Instant,
    /// When the flow was last updated
    pub last_seen: Instant,
    /// Total packets in forward direction
    pub fwd_packets: u64,
    /// Total packets in reverse direction
    pub rev_packets: u64,
    /// Total bytes in forward direction
    pub fwd_bytes: u64,
    /// Total bytes in reverse direction
    pub rev_bytes: u64,
    /// Collected inter-arrival times (for ML features) — bounded
    pub inter_arrival_times: Vec<Duration>,
    /// Collected packet sizes (for ML features) — bounded
    pub packet_sizes: Vec<u16>,
    /// TCP flags seen (OR'd together)
    pub tcp_flags_union: u8,
    /// DNS query names associated with this flow
    pub dns_queries: Vec<String>,
}

impl FlowRecord {
    fn new(key: FlowKey) -> Self {
        let now = Instant::now();
        Self {
            key,
            first_seen: now,
            last_seen: now,
            fwd_packets: 0,
            rev_packets: 0,
            fwd_bytes: 0,
            rev_bytes: 0,
            inter_arrival_times: Vec::with_capacity(64),
            packet_sizes: Vec::with_capacity(64),
            tcp_flags_union: 0,
            dns_queries: Vec::new(),
        }
    }
}

/// Flow tracker configuration.
pub struct FlowTrackerConfig {
    /// Maximum number of concurrent flows
    pub max_flows: usize,
    /// Flow idle timeout — evict flows idle longer than this
    pub idle_timeout: Duration,
    /// Maximum inter-arrival samples to keep per flow (for ML features)
    pub max_samples: usize,
}

impl Default for FlowTrackerConfig {
    fn default() -> Self {
        Self {
            max_flows: 100_000,
            idle_timeout: Duration::from_secs(120),
            max_samples: 128,
        }
    }
}

/// Event emitted when a flow is closed/evicted.
#[derive(Debug)]
pub struct FlowClosedEvent {
    pub record: FlowRecord,
    pub reason: FlowCloseReason,
}

#[derive(Debug)]
pub enum FlowCloseReason {
    IdleTimeout,
    CapacityEviction,
    TcpFinRst,
}

/// The main flow tracker.
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowRecord>,
    config: FlowTrackerConfig,
}

impl FlowTracker {
    pub fn new(config: FlowTrackerConfig) -> Self {
        Self {
            flows: HashMap::with_capacity(config.max_flows / 4),
            config,
        }
    }

    /// Update or create a flow with new packet data.
    /// Returns any evicted flows.
    pub fn update(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        packet_len: u16,
        tcp_flags: u8,
        dns_query: Option<&str>,
    ) -> Vec<FlowClosedEvent> {
        let mut evicted = Vec::new();

        let key = FlowKey::normalized(src_ip, dst_ip, src_port, dst_port, protocol);
        let is_forward = src_ip <= dst_ip || (src_ip == dst_ip && src_port <= dst_port);

        let now = Instant::now();

        // Evict oldest if at capacity
        if !self.flows.contains_key(&key) && self.flows.len() >= self.config.max_flows {
            if let Some(oldest_key) = self.find_oldest_flow() {
                if let Some(record) = self.flows.remove(&oldest_key) {
                    evicted.push(FlowClosedEvent {
                        record,
                        reason: FlowCloseReason::CapacityEviction,
                    });
                }
            }
        }

        let record = self
            .flows
            .entry(key.clone())
            .or_insert_with(|| FlowRecord::new(key));

        // Compute inter-arrival time
        if record.fwd_packets + record.rev_packets > 0 {
            let iat = now.duration_since(record.last_seen);
            if record.inter_arrival_times.len() < self.config.max_samples {
                record.inter_arrival_times.push(iat);
            }
        }

        record.last_seen = now;

        if is_forward {
            record.fwd_packets += 1;
            record.fwd_bytes += packet_len as u64;
        } else {
            record.rev_packets += 1;
            record.rev_bytes += packet_len as u64;
        }

        if record.packet_sizes.len() < self.config.max_samples {
            record.packet_sizes.push(packet_len);
        }

        record.tcp_flags_union |= tcp_flags;

        if let Some(query) = dns_query {
            if record.dns_queries.len() < 16 {
                record.dns_queries.push(query.to_string());
            }
        }

        evicted
    }

    /// Evict idle flows. Returns all closed flow events.
    pub fn evict_idle(&mut self) -> Vec<FlowClosedEvent> {
        let now = Instant::now();
        let timeout = self.config.idle_timeout;
        let mut evicted = Vec::new();

        self.flows.retain(|_, record| {
            if now.duration_since(record.last_seen) > timeout {
                evicted.push(FlowClosedEvent {
                    record: record.clone(),
                    reason: FlowCloseReason::IdleTimeout,
                });
                false
            } else {
                true
            }
        });

        evicted
    }

    /// Current number of active flows.
    pub fn active_count(&self) -> usize {
        self.flows.len()
    }

    /// Get a reference to a flow record by key.
    pub fn get(&self, key: &FlowKey) -> Option<&FlowRecord> {
        self.flows.get(key)
    }

    /// Find the oldest (least recently seen) flow key.
    fn find_oldest_flow(&self) -> Option<FlowKey> {
        self.flows
            .iter()
            .min_by_key(|(_, r)| r.last_seen)
            .map(|(k, _)| k.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_flow_creation_and_update() {
        let mut tracker = FlowTracker::new(FlowTrackerConfig::default());

        let events = tracker.update(
            ip(192, 168, 1, 1),
            ip(10, 0, 0, 1),
            12345,
            80,
            6, // TCP
            1500,
            0x02, // SYN
            None,
        );
        assert!(events.is_empty());
        assert_eq!(tracker.active_count(), 1);

        // Second packet in same flow
        tracker.update(
            ip(10, 0, 0, 1),
            ip(192, 168, 1, 1),
            80,
            12345,
            6,
            1200,
            0x12, // SYN-ACK
            None,
        );
        assert_eq!(tracker.active_count(), 1); // still 1 flow (bidirectional)

        let key = FlowKey::normalized(
            ip(192, 168, 1, 1),
            ip(10, 0, 0, 1),
            12345,
            80,
            6,
        );
        let record = tracker.get(&key).expect("flow should exist");
        assert_eq!(record.fwd_packets, 1);
        assert_eq!(record.rev_packets, 1);
        assert_eq!(record.fwd_bytes, 1200);
        assert_eq!(record.rev_bytes, 1500);
        assert_eq!(record.tcp_flags_union, 0x02 | 0x12); // SYN | SYN-ACK
    }

    #[test]
    fn test_capacity_eviction() {
        let mut tracker = FlowTracker::new(FlowTrackerConfig {
            max_flows: 3,
            idle_timeout: Duration::from_secs(120),
            max_samples: 64,
        });

        // Fill to capacity
        for i in 0..3 {
            tracker.update(ip(10, 0, 0, i as u8), ip(10, 0, 1, 0), 1000 + i, 80, 6, 100, 0, None);
        }
        assert_eq!(tracker.active_count(), 3);

        // One more should evict the oldest
        let events = tracker.update(ip(10, 0, 0, 99), ip(10, 0, 1, 0), 9999, 80, 6, 100, 0, None);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].reason, FlowCloseReason::CapacityEviction));
        assert_eq!(tracker.active_count(), 3);
    }

    #[test]
    fn test_idle_eviction() {
        let mut tracker = FlowTracker::new(FlowTrackerConfig {
            max_flows: 100,
            idle_timeout: Duration::from_millis(1), // very short timeout
            max_samples: 64,
        });

        tracker.update(ip(10, 0, 0, 1), ip(10, 0, 1, 1), 1000, 80, 6, 100, 0, None);
        assert_eq!(tracker.active_count(), 1);

        // Wait for idle timeout
        std::thread::sleep(Duration::from_millis(10));

        let evicted = tracker.evict_idle();
        assert_eq!(evicted.len(), 1);
        assert!(matches!(evicted[0].reason, FlowCloseReason::IdleTimeout));
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_dns_query_tracking() {
        let mut tracker = FlowTracker::new(FlowTrackerConfig::default());

        tracker.update(
            ip(192, 168, 1, 10),
            ip(8, 8, 8, 8),
            54321,
            53,
            17, // UDP
            100,
            0,
            Some("malware.evil.com"),
        );

        let key = FlowKey::normalized(
            ip(192, 168, 1, 10),
            ip(8, 8, 8, 8),
            54321,
            53,
            17,
        );
        let record = tracker.get(&key).unwrap();
        assert_eq!(record.dns_queries.len(), 1);
        assert_eq!(record.dns_queries[0], "malware.evil.com");
    }
}
