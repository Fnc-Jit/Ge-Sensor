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
use crate::flow::features;
use crate::flow::tracker::FlowTracker;
use crate::ips::{IpsEngine, IpsMode, IpsRule, RuleCriteria, Verdict};
use crate::pcap_store::ring_buffer::PacketRingBuffer;
use crate::utils::logging::Metrics;

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ── Packet Ring Buffer ───────────────────────────────────────────────────

/// Maximum number of recent packets stored for the dashboard.
const MAX_RECENT_PACKETS: usize = 500;
/// Maximum number of recent IPS events stored for the dashboard.
const MAX_IPS_EVENTS: usize = 300;
/// Maximum number of capture records retained in memory for PCAP page.
const MAX_PCAP_RECORDS: usize = 500;

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

/// A single IPS match event for the live block feed.
#[derive(Debug, Clone, Serialize)]
pub struct IpsEventRecord {
    pub time_secs: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub verdict: String,
    pub rule_id: String,
    pub severity: String,
    pub description: String,
}

/// Thread-safe ring buffer for recent IPS events.
pub struct IpsEventRing {
    events: VecDeque<IpsEventRecord>,
}

/// Metadata for one persisted PCAP capture.
#[derive(Debug, Clone, Serialize)]
pub struct PcapCaptureRecord {
    pub capture_id: String,
    pub trigger_type: String,
    pub five_tuple: String,
    pub size_bytes: u64,
    pub duration_secs: f64,
    pub timestamp: u64,
    pub status: String,
    pub file_name: String,
    pub file_path: String,
    pub rule_id: String,
}

/// Aggregated PCAP storage status for the dashboard tab.
#[derive(Debug, Serialize)]
pub struct PcapStorageResponse {
    pub stored_captures: usize,
    pub total_size_bytes: u64,
    pub ring_buffer_mb: u32,
    pub ring_buffer_used_pct: f64,
    pub ring_buffer_used_bytes: usize,
    pub trigger_mode: String,
    pub retention_days: u32,
    pub index_type: String,
    pub storage_backend: String,
    pub compression: String,
    pub max_capture_mb: u32,
    pub today_captures: usize,
    pub alert_triggered: usize,
    pub manual_captures: usize,
    pub captures: Vec<PcapCaptureRecord>,
}

#[derive(Debug, Deserialize)]
pub struct PcapBulkDownloadRequest {
    pub ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PcapBulkDownloadResponse {
    pub ok: bool,
    pub selected: usize,
    pub total_size_bytes: u64,
    pub files: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PcapDownloadResponse {
    pub ok: bool,
    pub capture_id: String,
    pub file_path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct PcapReconstructResponse {
    pub ok: bool,
    pub capture_id: String,
    pub summary: String,
    pub five_tuple: String,
    pub estimated_packets: u64,
    pub duration_secs: f64,
}

impl IpsEventRing {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_IPS_EVENTS),
        }
    }

    pub fn push(&mut self, event: IpsEventRecord) {
        if self.events.len() >= MAX_IPS_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn recent(&self) -> Vec<IpsEventRecord> {
        self.events.iter().cloned().collect()
    }
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
    /// Ring buffer of recent IPS events for live block feed.
    pub ips_event_ring: Arc<Mutex<IpsEventRing>>,
    /// Packet byte ring used to build forensic PCAP captures.
    pub pcap_ring: Arc<Mutex<PacketRingBuffer>>,
    /// Metadata records for saved PCAP captures.
    pub pcap_captures: Arc<Mutex<VecDeque<PcapCaptureRecord>>>,
    /// On-disk capture output directory.
    pub pcap_output_dir: Arc<RwLock<PathBuf>>,
    /// Monotonic sequence for capture IDs.
    pub pcap_seq: Arc<AtomicU64>,
    /// Runtime capture toggle (on/off).
    pub capture_enabled: Arc<std::sync::atomic::AtomicBool>,
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
    pub snap_len: u32, pub packets_total: i64, pub capturing: bool,
}

#[derive(Serialize)]
pub struct FlowInfo { pub active_flows: i64 }

#[derive(Clone, Serialize)]
pub struct IpsInfo {
    pub mode: String, pub enabled: bool, pub default_action: String,
    pub rules_count: usize, pub packets_inspected: u64,
    pub packets_passed: u64, pub packets_dropped: u64, pub packets_alerted: u64,
}

#[derive(Serialize)]
pub struct IpsRulesResponse {
    pub mode: String,
    pub rules_count: usize,
    pub total_rule_hits: u64,
    pub rules: Vec<IpsRuleApi>,
}

#[derive(Serialize)]
pub struct IpsRuleApi {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub action: String,
    pub enabled: bool,
    pub hits: u64,
    pub match_summary: String,
    pub status: String,
}

#[derive(Deserialize)]
pub struct NewIpsRuleRequest {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub action: String,
    #[serde(default = "default_true_bool")]
    pub enabled: bool,
    #[serde(default)]
    pub criteria: RuleCriteriaRequest,
}

#[derive(Deserialize, Default)]
pub struct RuleCriteriaRequest {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub tcp_flags_mask: Option<u8>,
    pub tcp_flags_value: Option<u8>,
    #[serde(default)]
    pub modbus_func_codes: Vec<u8>,
    #[serde(default)]
    pub dnp3_func_codes: Vec<u8>,
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

/// A single flow record for the Flow Tracker API.
#[derive(Serialize)]
pub struct FlowDetailRecord {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub fwd_packets: u64,
    pub rev_packets: u64,
    pub fwd_bytes: u64,
    pub rev_bytes: u64,
    pub duration_secs: f64,
    pub bytes_ratio: f32,
    pub dns_entropy: f32,
    pub beaconing_score: f32,
    pub conn_rate: f32,
    pub off_hours_pct: f32,
    pub ml_score: f32,
}

/// Aggregated flows response for `/api/flows`.
#[derive(Serialize)]
pub struct FlowsResponse {
    pub total_flows: usize,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub anomalous: usize,
    pub avg_duration: f64,
    pub flows: Vec<FlowDetailRecord>,
}

impl AppState {
    pub fn capture_enabled(&self) -> bool {
        self.capture_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_capture_enabled(&self, enabled: bool) -> bool {
        self.capture_enabled
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
        enabled
    }

    fn build_ips_info(&self) -> IpsInfo {
        let engine = self.ips_engine.lock().unwrap();
        let stats = engine.stats();
        let cfg = self.config.read().unwrap();

        IpsInfo {
            mode: match engine.mode() {
                IpsMode::Tap => "tap".to_string(),
                IpsMode::Inline => "inline".to_string(),
            },
            enabled: cfg.ips.enabled,
            default_action: cfg.ips.default_action.clone(),
            rules_count: engine.rule_count(),
            packets_inspected: stats.packets_inspected,
            packets_passed: stats.packets_passed,
            packets_dropped: stats.packets_dropped,
            packets_alerted: stats.packets_alerted,
        }
    }

    pub fn ips_info(&self) -> IpsInfo {
        self.build_ips_info()
    }

    pub fn ips_rules(&self) -> IpsRulesResponse {
        let engine = self.ips_engine.lock().unwrap();
        let mode = engine.mode();

        let rules: Vec<IpsRuleApi> = engine
            .rules()
            .iter()
            .map(|rule| {
                let hits = engine.rule_hit_count(&rule.id);
                let action = verdict_to_str(rule.action).to_string();
                let status = match (mode, rule.action, rule.enabled) {
                    (_, _, false) => "disabled",
                    (IpsMode::Tap, Verdict::Drop, true) => "tap_only",
                    (IpsMode::Inline, Verdict::Drop, true) => "blocking",
                    (_, Verdict::Alert, true) => "alert_only",
                    (_, Verdict::Pass, true) => "pass",
                }
                .to_string();

                IpsRuleApi {
                    id: rule.id.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    action,
                    enabled: rule.enabled,
                    hits,
                    match_summary: summarize_rule(rule),
                    status,
                }
            })
            .collect();

        let total_rule_hits = rules.iter().map(|r| r.hits).sum();

        IpsRulesResponse {
            mode: match mode {
                IpsMode::Tap => "tap".to_string(),
                IpsMode::Inline => "inline".to_string(),
            },
            rules_count: rules.len(),
            total_rule_hits,
            rules,
        }
    }

    pub fn set_ips_mode(&self, mode: &str) -> Result<IpsInfo, String> {
        let normalized = mode.trim().to_ascii_lowercase();
        let new_mode = match normalized.as_str() {
            "tap" => IpsMode::Tap,
            "inline" => IpsMode::Inline,
            _ => return Err("mode must be 'tap' or 'inline'".to_string()),
        };

        {
            let mut engine = self.ips_engine.lock().unwrap();
            engine.set_mode(new_mode);
        }

        {
            let mut cfg = self.config.write().unwrap();
            cfg.ips.mode = normalized;
            cfg.ips.enabled = true;
        }

        Ok(self.build_ips_info())
    }

    pub fn add_ips_rule(&self, req: NewIpsRuleRequest) -> Result<IpsRuleApi, String> {
        let rule = req.into_rule()?;
        let rule_id = rule.id.clone();

        {
            let mut engine = self.ips_engine.lock().unwrap();
            if engine.rules().iter().any(|r| r.id == rule_id) {
                return Err(format!("rule '{}' already exists", rule_id));
            }
            engine.add_rule(rule);
        }

        self.ips_rules()
            .rules
            .into_iter()
            .find(|r| r.id == rule_id)
            .ok_or_else(|| "failed to read added rule".to_string())
    }

    pub fn delete_ips_rule(&self, rule_id: &str) -> Result<(), String> {
        let mut engine = self.ips_engine.lock().unwrap();
        if engine.remove_rule(rule_id) {
            Ok(())
        } else {
            Err(format!("rule '{}' not found", rule_id))
        }
    }

    pub fn recent_ips_events(&self) -> Vec<IpsEventRecord> {
        self.ips_event_ring.lock().unwrap().recent()
    }

    pub fn pcap_push_packet_bytes(&self, packet: &[u8]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut ring = self.pcap_ring.lock().unwrap();
        ring.push(ts.as_secs() as u32, ts.subsec_micros(), packet);
    }

    pub fn create_pcap_capture(
        &self,
        trigger_type: &str,
        five_tuple: &str,
        rule_id: Option<&str>,
    ) -> Result<PcapCaptureRecord, String> {
        let capture_no = self.pcap_seq.fetch_add(1, Ordering::SeqCst);
        let capture_id = format!("ALT-{capture_no:04}");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let file_name = format!("{capture_id}.pcap");
        let file_path = self.pcap_output_dir.read().unwrap().join(&file_name);

        let packets_written = {
            let ring = self.pcap_ring.lock().unwrap();
            ring.flush_to_pcap(&file_path)
                .map_err(|e| format!("failed to write pcap: {e}"))?
        };

        let size_bytes = std::fs::metadata(&file_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let duration_secs = self.start_time.elapsed().as_secs_f64();
        let record = PcapCaptureRecord {
            capture_id,
            trigger_type: trigger_type.to_string(),
            five_tuple: five_tuple.to_string(),
            size_bytes,
            duration_secs,
            timestamp,
            status: "indexed".to_string(),
            file_name,
            file_path: file_path.to_string_lossy().to_string(),
            rule_id: rule_id.unwrap_or("").to_string(),
        };

        {
            let mut captures = self.pcap_captures.lock().unwrap();
            if captures.len() >= MAX_PCAP_RECORDS {
                if let Some(old) = captures.pop_front() {
                    let _ = std::fs::remove_file(old.file_path);
                }
            }
            captures.push_back(record.clone());
        }

        Ok(record)
    }

    pub fn pcap_storage(&self, filter: Option<&str>) -> PcapStorageResponse {
        let cfg = self.config.read().unwrap();
        let captures_guard = self.pcap_captures.lock().unwrap();
        let mut captures: Vec<PcapCaptureRecord> = captures_guard.iter().cloned().collect();

        if let Some(f) = filter {
            let needle = f.to_ascii_lowercase();
            if !needle.is_empty() {
                captures.retain(|c| {
                    c.capture_id.to_ascii_lowercase().contains(&needle)
                        || c.five_tuple.to_ascii_lowercase().contains(&needle)
                        || c.rule_id.to_ascii_lowercase().contains(&needle)
                        || c.trigger_type.to_ascii_lowercase().contains(&needle)
                });
            }
        }

        let total_size_bytes: u64 = captures.iter().map(|c| c.size_bytes).sum();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let today_captures = captures
            .iter()
            .filter(|c| now.saturating_sub(c.timestamp) <= 86_400)
            .count();
        let alert_triggered = captures
            .iter()
            .filter(|c| c.trigger_type.eq_ignore_ascii_case("alert"))
            .count();
        let manual_captures = captures
            .iter()
            .filter(|c| c.trigger_type.eq_ignore_ascii_case("manual"))
            .count();

        let ring_used_bytes = self.pcap_ring.lock().unwrap().bytes_used();
        let ring_alloc_bytes = (cfg.pcap.ring_buffer_mb as usize) * 1024 * 1024;
        let ring_buffer_used_pct = if ring_alloc_bytes == 0 {
            0.0
        } else {
            (ring_used_bytes as f64 / ring_alloc_bytes as f64) * 100.0
        };

        PcapStorageResponse {
            stored_captures: captures.len(),
            total_size_bytes,
            ring_buffer_mb: cfg.pcap.ring_buffer_mb,
            ring_buffer_used_pct,
            ring_buffer_used_bytes: ring_used_bytes,
            trigger_mode: cfg.pcap.trigger.clone(),
            retention_days: cfg.pcap.retention_days,
            index_type: "5-tuple + timestamp".to_string(),
            storage_backend: "filesystem + ring buffer".to_string(),
            compression: "none".to_string(),
            max_capture_mb: 50,
            today_captures,
            alert_triggered,
            manual_captures,
            captures,
        }
    }

    pub fn pcap_download(&self, capture_id: &str) -> Result<PcapDownloadResponse, String> {
        let captures = self.pcap_captures.lock().unwrap();
        let cap = captures
            .iter()
            .find(|c| c.capture_id == capture_id)
            .ok_or_else(|| format!("capture '{}' not found", capture_id))?;
        Ok(PcapDownloadResponse {
            ok: true,
            capture_id: cap.capture_id.clone(),
            file_path: cap.file_path.clone(),
            size_bytes: cap.size_bytes,
        })
    }

    pub fn pcap_bulk_download(&self, ids: &[String]) -> PcapBulkDownloadResponse {
        let captures = self.pcap_captures.lock().unwrap();
        let mut files = Vec::new();
        let mut total_size_bytes = 0u64;

        for id in ids {
            if let Some(c) = captures.iter().find(|x| x.capture_id == *id) {
                files.push(c.file_path.clone());
                total_size_bytes += c.size_bytes;
            }
        }

        PcapBulkDownloadResponse {
            ok: true,
            selected: files.len(),
            total_size_bytes,
            files,
        }
    }

    pub fn pcap_reconstruct(&self, capture_id: &str) -> Result<PcapReconstructResponse, String> {
        let captures = self.pcap_captures.lock().unwrap();
        let cap = captures
            .iter()
            .find(|c| c.capture_id == capture_id)
            .ok_or_else(|| format!("capture '{}' not found", capture_id))?;

        Ok(PcapReconstructResponse {
            ok: true,
            capture_id: cap.capture_id.clone(),
            summary: format!(
                "Reconstructed session for {} ({})",
                cap.five_tuple, cap.trigger_type
            ),
            five_tuple: cap.five_tuple.clone(),
            estimated_packets: cap.size_bytes / 128,
            duration_secs: cap.duration_secs,
        })
    }

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

    /// Build the flows response with per-flow ML features.
    pub fn flow_details(&self) -> FlowsResponse {
        let tracker = self.flow_tracker.lock().unwrap();
        let now = std::time::Instant::now();

        let mut flow_records = Vec::new();
        let mut tcp_count = 0usize;
        let mut udp_count = 0usize;
        let mut total_duration = 0.0f64;

        let all_flows = tracker.all_flows();

        for record in &all_flows {
            let feats = features::extract_features(record);

            let proto_name = match record.key.protocol {
                6 => { tcp_count += 1; "TCP" }
                17 => { udp_count += 1; "UDP" }
                1 => "ICMP",
                _ => "OTHER",
            };

            let duration = now.duration_since(record.first_seen).as_secs_f64();
            total_duration += duration;

            // Compute composite ML score: weighted average of key anomaly features
            let ml_score = (
                feats[features::idx::BEACONING_SCORE] * 0.25 +
                feats[features::idx::DNS_ENTROPY].min(5.0) / 5.0 * 0.15 +
                feats[features::idx::TRAFFIC_ASYMMETRY] * 0.15 +
                feats[features::idx::TCP_FLAG_ANOMALY] * 0.25 +
                feats[features::idx::OFF_HOURS_PCT] * 0.10 +
                (feats[features::idx::CONN_RATE].min(1000.0) / 1000.0) * 0.10
            ).min(1.0);

            flow_records.push(FlowDetailRecord {
                src_ip: record.key.src_ip.to_string(),
                dst_ip: record.key.dst_ip.to_string(),
                src_port: record.key.src_port,
                dst_port: record.key.dst_port,
                protocol: proto_name.to_string(),
                fwd_packets: record.fwd_packets,
                rev_packets: record.rev_packets,
                fwd_bytes: record.fwd_bytes,
                rev_bytes: record.rev_bytes,
                duration_secs: duration,
                bytes_ratio: feats[features::idx::BYTES_RATIO],
                dns_entropy: feats[features::idx::DNS_ENTROPY],
                beaconing_score: feats[features::idx::BEACONING_SCORE],
                conn_rate: feats[features::idx::CONN_RATE],
                off_hours_pct: feats[features::idx::OFF_HOURS_PCT],
                ml_score,
            });
        }

        // Sort by ml_score descending
        flow_records.sort_by(|a, b| b.ml_score.partial_cmp(&a.ml_score).unwrap_or(std::cmp::Ordering::Equal));

        let total = flow_records.len();
        let anomalous = flow_records.iter().filter(|f| f.ml_score > 0.5).count();
        let avg_duration = if total > 0 { total_duration / total as f64 } else { 0.0 };

        FlowsResponse {
            total_flows: total,
            tcp_flows: tcp_count,
            udp_flows: udp_count,
            anomalous,
            avg_duration,
            flows: flow_records,
        }
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

        let ips_info = self.build_ips_info();

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
                capturing: self.capture_enabled(),
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

fn verdict_to_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "pass",
        Verdict::Drop => "drop",
        Verdict::Alert => "alert",
    }
}

fn summarize_rule(rule: &IpsRule) -> String {
    let mut parts: Vec<String> = Vec::new();
    let c = &rule.criteria;

    if let Some(ip) = c.src_ip {
        parts.push(format!("src_ip={ip}"));
    }
    if let Some(ip) = c.dst_ip {
        parts.push(format!("dst_ip={ip}"));
    }
    if let Some(port) = c.src_port {
        parts.push(format!("src_port={port}"));
    }
    if let Some(port) = c.dst_port {
        parts.push(format!("dst_port={port}"));
    }
    if let Some(proto) = c.protocol {
        parts.push(format!("proto={proto}"));
    }
    if let (Some(mask), Some(value)) = (c.tcp_flags_mask, c.tcp_flags_value) {
        parts.push(format!("tcp_flags({mask:#04x})={value:#04x}"));
    }
    if !c.modbus_func_codes.is_empty() {
        parts.push(format!("modbus_fc={:?}", c.modbus_func_codes));
    }
    if !c.dnp3_func_codes.is_empty() {
        parts.push(format!("dnp3_fc={:?}", c.dnp3_func_codes));
    }

    if parts.is_empty() {
        "any".to_string()
    } else {
        parts.join(", ")
    }
}

impl NewIpsRuleRequest {
    fn into_rule(self) -> Result<IpsRule, String> {
        let id = self.id.trim().to_string();
        if id.is_empty() {
            return Err("rule id must not be empty".to_string());
        }

        let description = self.description.trim().to_string();
        if description.is_empty() {
            return Err("rule description must not be empty".to_string());
        }

        let action = match self.action.trim().to_ascii_lowercase().as_str() {
            "drop" => Verdict::Drop,
            "alert" => Verdict::Alert,
            "pass" => Verdict::Pass,
            _ => return Err("action must be one of: drop, alert, pass".to_string()),
        };

        Ok(IpsRule {
            id,
            description,
            severity: self.severity.trim().to_ascii_lowercase(),
            action,
            criteria: self.criteria.into_criteria()?,
            enabled: self.enabled,
        })
    }
}

impl RuleCriteriaRequest {
    fn into_criteria(self) -> Result<RuleCriteria, String> {
        Ok(RuleCriteria {
            src_ip: parse_optional_ip(self.src_ip, "src_ip")?,
            dst_ip: parse_optional_ip(self.dst_ip, "dst_ip")?,
            src_port: self.src_port,
            dst_port: self.dst_port,
            protocol: self.protocol,
            tcp_flags_mask: self.tcp_flags_mask,
            tcp_flags_value: self.tcp_flags_value,
            modbus_func_codes: self.modbus_func_codes,
            dnp3_func_codes: self.dnp3_func_codes,
        })
    }
}

fn parse_optional_ip(value: Option<String>, field: &str) -> Result<Option<IpAddr>, String> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            trimmed
                .parse::<IpAddr>()
                .map(Some)
                .map_err(|_| format!("invalid {} address", field))
        }
    }
}

fn default_true_bool() -> bool {
    true
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
