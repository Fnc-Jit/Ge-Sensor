//! Embedded dashboard for ge-sensor.
//!
//! Serves a real-time monitoring UI at `GET /` with live data from the sensor.
//! All data comes from the actual runtime state via JSON API endpoints:
//!   GET  /api/state        → full sensor state snapshot
//!   GET  /api/packets      → recent captured packets (Wireshark-style)
//!   GET  /api/interfaces   → list available capture interfaces
//!   GET  /api/set-interface?iface=<name>  → switch capture interface
//!   GET  /metrics          → Prometheus text format
//!   GET  /health           → JSON health check

use crate::config::Config;
use crate::flow::tracker::FlowTracker;
use crate::ips::{IpsEngine, IpsMode, Verdict};
use crate::utils::logging::Metrics;

use serde::Serialize;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

// ── Packet Ring Buffer ───────────────────────────────────────────────────

/// Maximum number of recent packets stored for the dashboard.
const MAX_RECENT_PACKETS: usize = 500;

/// A captured+dissected packet ready for display.
#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    /// Monotonic packet number
    pub no: u64,
    /// Seconds since sensor start (high-res)
    pub time_secs: f64,
    /// Source IP
    pub src_ip: String,
    /// Destination IP
    pub dst_ip: String,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol name (tcp, udp, icmp, dns, http, tls, etc.)
    pub protocol: String,
    /// Total packet length on wire
    pub length: u32,
    /// Human-readable info line (like Wireshark's Info column)
    pub info: String,
    /// TCP flags as string (SYN, ACK, FIN, RST, PSH, etc.)
    pub tcp_flags: String,
    /// IP TTL / Hop Limit
    pub ttl: u8,
    /// Source MAC address
    pub src_mac: String,
    /// Destination MAC address
    pub dst_mac: String,
    /// VLAN ID if present
    pub vlan_id: Option<u16>,
    /// EtherType (hex string)
    pub ethertype: String,
    /// IP protocol number
    pub ip_proto: u8,
    /// Payload size (L4 payload)
    pub payload_len: usize,
    /// TCP sequence number
    pub tcp_seq: u32,
    /// TCP ack number
    pub tcp_ack: u32,
    /// TCP window size
    pub tcp_window: u16,
    /// IPS verdict if any
    pub ips_verdict: String,
    /// IPS rule ID if matched
    pub ips_rule: String,
}

/// Thread-safe ring buffer for recent packets.
pub struct PacketRing {
    packets: VecDeque<PacketRecord>,
    counter: u64,
}

impl PacketRing {
    pub fn new() -> Self {
        Self {
            packets: VecDeque::with_capacity(MAX_RECENT_PACKETS),
            counter: 0,
        }
    }

    /// Push a new packet into the ring buffer.
    pub fn push(&mut self, mut record: PacketRecord) {
        self.counter += 1;
        record.no = self.counter;
        if self.packets.len() >= MAX_RECENT_PACKETS {
            self.packets.pop_front();
        }
        self.packets.push_back(record);
    }

    /// Get all recent packets (newest last).
    pub fn recent(&self) -> Vec<PacketRecord> {
        self.packets.iter().cloned().collect()
    }

    /// Total packets seen (not just buffered).
    pub fn total_count(&self) -> u64 {
        self.counter
    }
}

/// Build a human-readable info string like Wireshark does.
pub fn build_packet_info(meta: &crate::dissectors::PacketMetadata, pkt_len: u32) -> String {
    match meta.protocol_name {
        "tcp" | "tcp_truncated" => {
            let flags = format_tcp_flags(meta.tcp_flags);
            format!(
                "{} → {} [{}] Seq={} Ack={} Win={} Len={}",
                meta.src_port, meta.dst_port, flags,
                meta.tcp_seq, meta.tcp_ack, meta.tcp_window,
                meta.payload_len
            )
        }
        "udp" => {
            format!(
                "{} → {} Len={}",
                meta.src_port, meta.dst_port, meta.payload_len
            )
        }
        "dns" => {
            format!(
                "DNS {} → {} Len={}",
                meta.src_port, meta.dst_port, meta.payload_len
            )
        }
        "http" => {
            let flags = format_tcp_flags(meta.tcp_flags);
            format!(
                "HTTP {} → {} [{}] Len={}",
                meta.src_port, meta.dst_port, flags, meta.payload_len
            )
        }
        "tls" => {
            let flags = format_tcp_flags(meta.tcp_flags);
            format!(
                "TLS {} → {} [{}] Len={}",
                meta.src_port, meta.dst_port, flags, meta.payload_len
            )
        }
        "ntp" => {
            format!(
                "NTP {} → {} Len={}",
                meta.src_port, meta.dst_port, meta.payload_len
            )
        }
        "dhcp" => {
            format!(
                "DHCP {} → {} Len={}",
                meta.src_port, meta.dst_port, meta.payload_len
            )
        }
        "quic" => {
            format!(
                "QUIC {} → {} Len={}",
                meta.src_port, meta.dst_port, meta.payload_len
            )
        }
        "icmp" => {
            format!("ICMP type={} code={}", meta.icmp_type, meta.icmp_code)
        }
        _ => {
            format!("Proto={} Len={}", meta.ip_proto, pkt_len)
        }
    }
}

/// Format TCP flags into Wireshark-style string.
pub fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x02 != 0 { parts.push("SYN"); }
    if flags & 0x10 != 0 { parts.push("ACK"); }
    if flags & 0x01 != 0 { parts.push("FIN"); }
    if flags & 0x04 != 0 { parts.push("RST"); }
    if flags & 0x08 != 0 { parts.push("PSH"); }
    if flags & 0x20 != 0 { parts.push("URG"); }
    if flags & 0x40 != 0 { parts.push("ECE"); }
    if flags & 0x80 != 0 { parts.push("CWR"); }
    if parts.is_empty() { parts.push("none"); }
    parts.join(", ")
}

/// Format MAC address bytes.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Build a PacketRecord from dissected metadata.
pub fn build_packet_record(
    meta: &crate::dissectors::PacketMetadata,
    pkt_len: u32,
    elapsed_secs: f64,
    verdict: &Verdict,
    rule_id: &str,
) -> PacketRecord {
    PacketRecord {
        no: 0,  // set by ring buffer
        time_secs: elapsed_secs,
        src_ip: meta.src_ip.map(|i| i.to_string()).unwrap_or_else(|| "—".into()),
        dst_ip: meta.dst_ip.map(|i| i.to_string()).unwrap_or_else(|| "—".into()),
        src_port: meta.src_port,
        dst_port: meta.dst_port,
        protocol: meta.protocol_name.to_uppercase(),
        length: pkt_len,
        info: build_packet_info(meta, pkt_len),
        tcp_flags: format_tcp_flags(meta.tcp_flags),
        ttl: meta.ip_ttl,
        src_mac: format_mac(&meta.src_mac),
        dst_mac: format_mac(&meta.dst_mac),
        vlan_id: meta.vlan_id,
        ethertype: format!("0x{:04X}", meta.ethertype),
        ip_proto: meta.ip_proto,
        payload_len: meta.payload_len,
        tcp_seq: meta.tcp_seq,
        tcp_ack: meta.tcp_ack,
        tcp_window: meta.tcp_window,
        ips_verdict: format!("{:?}", verdict),
        ips_rule: rule_id.to_string(),
    }
}

// ── App State ────────────────────────────────────────────────────────────

/// Shared application state — wired to real runtime components.
pub struct AppState {
    pub metrics: Arc<Metrics>,
    pub flow_tracker: Arc<Mutex<FlowTracker>>,
    pub ips_engine: Arc<Mutex<IpsEngine>>,
    pub config: Arc<RwLock<Config>>,
    pub start_time: Instant,
    pub sensor_name: String,
    pub capture_interface: Arc<RwLock<String>>,
    pub capture_mode: String,
    pub restart_capture: Arc<std::sync::atomic::AtomicBool>,
    /// Ring buffer of recent captured packets for the Packets tab.
    pub packet_ring: Arc<Mutex<PacketRing>>,
}

// ── JSON response types ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SensorStateResponse {
    pub sensor: SensorInfo,
    pub capture: CaptureInfo,
    pub flows: FlowInfo,
    pub ips: IpsInfo,
    pub kafka: KafkaInfo,
    pub dlq: DlqInfo,
    pub dissectors: Vec<DissectorInfo>,
    pub inputs: Vec<InputInfo>,
}

#[derive(Serialize)]
pub struct SensorInfo {
    pub name: String, pub version: String, pub uptime_secs: u64,
    pub status: String, pub ram_bytes: i64,
}

#[derive(Serialize)]
pub struct CaptureInfo {
    pub interface: String, pub mode: String, pub promiscuous: bool,
    pub snap_len: u32, pub packets_total: i64,
}

#[derive(Serialize)]
pub struct FlowInfo { pub active_flows: i64 }

#[derive(Serialize)]
pub struct IpsInfo {
    pub mode: String, pub enabled: bool, pub default_action: String,
    pub rules_count: usize, pub packets_inspected: u64,
    pub packets_passed: u64, pub packets_dropped: u64, pub packets_alerted: u64,
}

#[derive(Serialize)]
pub struct KafkaInfo {
    pub topic: String, pub brokers: Vec<String>, pub lag: i64, pub delivery_errors: i64,
}

#[derive(Serialize)]
pub struct DlqInfo { pub size_bytes: i64, pub total_spooled: u64 }

#[derive(Serialize)]
pub struct DissectorInfo {
    pub name: String, pub category: String, pub enabled: bool, pub port: String,
}

#[derive(Serialize)]
pub struct InputInfo {
    pub name: String, pub protocol: String, pub port: u16,
    pub enabled: bool, pub status: String,
}

#[derive(Serialize)]
pub struct InterfaceInfo {
    pub name: String, pub description: String, pub active: bool,
}

impl AppState {
    pub fn list_interfaces(&self) -> Vec<InterfaceInfo> {
        let current = self.capture_interface.read().unwrap().clone();
        pcap::Device::list()
            .unwrap_or_default()
            .into_iter()
            .map(|d| InterfaceInfo {
                active: d.name == current,
                description: d.desc.unwrap_or_default(),
                name: d.name,
            })
            .collect()
    }

    pub fn set_interface(&self, iface: &str) -> bool {
        let devices = pcap::Device::list().unwrap_or_default();
        if !devices.iter().any(|d| d.name == iface) { return false; }
        { let mut c = self.capture_interface.write().unwrap(); *c = iface.to_string(); }
        self.restart_capture.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    }

    pub fn recent_packets(&self) -> Vec<PacketRecord> {
        self.packet_ring.lock().unwrap().recent()
    }

    /// Toggle a dissector on or off at runtime
    pub fn toggle_dissector(&self, name: &str, state: bool) -> bool {
        let mut cfg = self.config.write().unwrap();
        match name.to_lowercase().as_str() {
            "tcp" => cfg.dissectors.tcp = state,
            "udp" => cfg.dissectors.udp = state,
            "icmp" => cfg.dissectors.icmp = state,
            "dns" => cfg.dissectors.dns = state,
            "http" => cfg.dissectors.http = state,
            "tls" => cfg.dissectors.tls = state,
            "ntp" => cfg.dissectors.ntp = state,
            "dhcp" => cfg.dissectors.dhcp = state,
            "modbus" => cfg.dissectors.modbus = state,
            "dnp3" => cfg.dissectors.dnp3 = state,
            "bacnet" | "bacnet/ip" => cfg.dissectors.bacnet = state,
            "ethernet/ip" | "enip" => cfg.dissectors.ethernet_ip = state,
            _ => return false,
        }
        true
    }

    pub fn snapshot(&self) -> SensorStateResponse {
        let uptime = self.start_time.elapsed();
        let metrics = &self.metrics;
        let current_iface = self.capture_interface.read().unwrap().clone();

        let packets_total = {
            let encoded = metrics.encode().unwrap_or_default();
            parse_prom_total(&encoded, "ge_packets_total")
        };

        let active_flows = {
            let tracker = self.flow_tracker.lock().unwrap();
            tracker.active_count() as i64
        };
        metrics.active_flows.set(active_flows);

        let ips_info = {
            let engine = self.ips_engine.lock().unwrap();
            let stats = engine.stats();
            IpsInfo {
                mode: match engine.mode() {
                    IpsMode::Tap => "tap".to_string(),
                    IpsMode::Inline => "inline".to_string(),
                },
                enabled: {
                    let cfg = self.config.read().unwrap();
                    cfg.ips.enabled
                },
                default_action: {
                    let cfg = self.config.read().unwrap();
                    cfg.ips.default_action.clone()
                },
                rules_count: engine.rule_count(),
                packets_inspected: stats.packets_inspected,
                packets_passed: stats.packets_passed,
                packets_dropped: stats.packets_dropped,
                packets_alerted: stats.packets_alerted,
            }
        };

        let cfg = self.config.read().unwrap();
        SensorStateResponse {
            sensor: SensorInfo {
                name: self.sensor_name.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: uptime.as_secs(),
                status: "running".to_string(),
                ram_bytes: metrics.ram_usage_bytes.get(),
            },
            capture: CaptureInfo {
                interface: current_iface,
                mode: self.capture_mode.clone(),
                promiscuous: cfg.capture.promisc,
                snap_len: cfg.capture.snap_len,
                packets_total,
            },
            flows: FlowInfo { active_flows },
            ips: ips_info,
            kafka: KafkaInfo {
                topic: cfg.output.kafka.topic.clone(),
                brokers: cfg.output.kafka.brokers.clone(),
                lag: metrics.kafka_lag.get(),
                delivery_errors: metrics.kafka_delivery_errors_total.get() as i64,
            },
            dlq: DlqInfo { size_bytes: metrics.dlq_size_bytes.get(), total_spooled: 0 },
            dissectors: build_dissector_list(&cfg),
            inputs: build_input_list(&cfg),
        }
    }
}

fn build_dissector_list(cfg: &Config) -> Vec<DissectorInfo> {
    let d = &cfg.dissectors;
    vec![
        DissectorInfo { name: "TCP".into(), category: "Transport".into(), enabled: d.tcp, port: "—".into() },
        DissectorInfo { name: "UDP".into(), category: "Transport".into(), enabled: d.udp, port: "—".into() },
        DissectorInfo { name: "ICMP".into(), category: "Network".into(), enabled: d.icmp, port: "—".into() },
        DissectorInfo { name: "DNS".into(), category: "Application".into(), enabled: d.dns, port: "53".into() },
        DissectorInfo { name: "HTTP".into(), category: "Application".into(), enabled: d.http, port: "80".into() },
        DissectorInfo { name: "TLS".into(), category: "Application".into(), enabled: d.tls, port: "443".into() },
        DissectorInfo { name: "NTP".into(), category: "Network".into(), enabled: d.ntp, port: "123".into() },
        DissectorInfo { name: "DHCP".into(), category: "Network".into(), enabled: d.dhcp, port: "67/68".into() },
        DissectorInfo { name: "Modbus TCP".into(), category: "OT/SCADA".into(), enabled: d.modbus, port: "502".into() },
        DissectorInfo { name: "DNP3".into(), category: "OT/SCADA".into(), enabled: d.dnp3, port: "20000".into() },
        DissectorInfo { name: "BACnet/IP".into(), category: "Building Mgmt".into(), enabled: d.bacnet, port: "47808".into() },
    ]
}

fn build_input_list(cfg: &Config) -> Vec<InputInfo> {
    let mut inputs = Vec::new();
    if let Some(ref s) = cfg.inputs.syslog {
        inputs.push(InputInfo {
            name: "Syslog".into(), protocol: s.protocol.clone(), port: s.port,
            enabled: s.enabled, status: if s.enabled { "listening".into() } else { "disabled".into() },
        });
    }
    if let Some(ref n) = cfg.inputs.netflow {
        inputs.push(InputInfo {
            name: "NetFlow v5".into(), protocol: n.protocol.clone(), port: n.port,
            enabled: n.enabled, status: if n.enabled { "listening".into() } else { "disabled".into() },
        });
    }
    if let Some(ref t) = cfg.inputs.snmp {
        inputs.push(InputInfo {
            name: "SNMP Traps".into(), protocol: t.protocol.clone(), port: t.port,
            enabled: t.enabled, status: if t.enabled { "listening".into() } else { "disabled".into() },
        });
    }
    if let Some(ref i) = cfg.inputs.ipfix {
        inputs.push(InputInfo {
            name: "IPFIX/NetFlow v9".into(), protocol: i.protocol.clone(), port: i.port,
            enabled: i.enabled, status: if i.enabled { "listening".into() } else { "disabled".into() },
        });
    }
    if let Some(ref w) = cfg.inputs.wef {
        inputs.push(InputInfo {
            name: "Windows Event Fwd".into(), protocol: w.protocol.clone(), port: w.port,
            enabled: w.enabled, status: if w.enabled { "listening".into() } else { "disabled".into() },
        });
    }
    if let Some(ref h) = cfg.inputs.http_webhook {
        inputs.push(InputInfo {
            name: "HTTP Webhook".into(), protocol: h.protocol.clone(), port: h.port,
            enabled: h.enabled, status: if h.enabled { "listening".into() } else { "disabled".into() },
        });
    }
    inputs
}

fn parse_prom_total(text: &str, metric_name: &str) -> i64 {
    let mut total: i64 = 0;
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() { continue; }
        if line.starts_with(metric_name) {
            if let Some(v) = line.split_whitespace().last() {
                if let Ok(n) = v.parse::<i64>() { total += n; }
            }
        }
    }
    total
}

pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");
