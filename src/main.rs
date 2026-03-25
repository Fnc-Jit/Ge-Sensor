#![allow(dead_code, unused_imports, unused_variables)]
//! ge-sensor — God's Eye network capture and IDS/IPS daemon.
//!
//! Full pipeline: libpcap → dissect → flow track → IPS → metrics.
//! Dashboard at / with runtime interface switching via /api/set-interface.

use anyhow::{Context, Result};
use clap::Parser;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

mod config;
mod capture;
mod dissectors;
mod flow;
mod inputs;
mod output;
mod pcap_store;
mod ips;
mod utils;

use config::Config;
use capture::{CaptureConfig, CaptureProvider};
use flow::tracker::{FlowTracker, FlowTrackerConfig};
use ips::{IpsEngine, IpsMode, Verdict};
use utils::dashboard::{
    AppState, IpsEventRecord, IpsEventRing, PacketRing, build_packet_record,
};
use utils::logging::Metrics;

#[derive(Parser)]
#[command(name = "ge-sensor", about = "God's Eye network sensor daemon")]
struct Cli {
    #[arg(short, long, default_value = "configs/ge-sensor.yml")]
    config: String,

    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: String,

    /// Override capture interface (e.g., en0, lo0, eth0)
    #[arg(short, long)]
    interface: Option<String>,
}

/// Detect the best available interface.
fn resolve_interface(configured: &str) -> String {
    let devices = pcap::Device::list().unwrap_or_default();
    if devices.iter().any(|d| d.name == configured) {
        return configured.to_string();
    }
    for preferred in &["en0", "lo0", "eth0", "wlan0"] {
        if devices.iter().any(|d| d.name == *preferred) {
            return preferred.to_string();
        }
    }
    devices.first().map(|d| d.name.clone()).unwrap_or_else(|| configured.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let start_time = Instant::now();

    let config = Config::load(&cli.config).context("failed to load configuration")?;

    let log_level = config.sensor.log_level.as_str();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "▶ Starting ge-sensor");

    // Resolve capture interface — CLI override > config > auto-detect
    let initial_iface = if let Some(ref iface) = cli.interface {
        iface.clone()
    } else {
        resolve_interface(&config.capture.interface)
    };
    info!(sensor = %config.sensor.name, interface = %initial_iface, mode = ?config.capture.mode, "configuration loaded");

    let metrics = Arc::new(Metrics::new().context("failed to init metrics")?);
    info!("Prometheus metrics initialized (8 families)");

    let flow_tracker = Arc::new(Mutex::new(FlowTracker::new(FlowTrackerConfig::default())));
    info!("flow tracker ready (max=100000, idle=120s)");

    let ips_mode = if config.ips.enabled {
        if config.ips.mode == "inline" { IpsMode::Inline } else { IpsMode::Tap }
    } else { IpsMode::Tap };
    let ips_engine = {
        let mut e = IpsEngine::new(ips_mode, Verdict::Pass);
        e.load_default_rules();
        Arc::new(Mutex::new(e))
    };
    info!(mode = ?ips_mode, rules = ips_engine.lock().unwrap().rule_count(), "IPS engine ready");

    // Shared mutable interface + restart flag
    let capture_interface = Arc::new(RwLock::new(initial_iface.clone()));
    let restart_capture = Arc::new(AtomicBool::new(false));

    let packet_ring = Arc::new(Mutex::new(PacketRing::new()));
    let ips_event_ring = Arc::new(Mutex::new(IpsEventRing::new()));
    let pcap_ring = Arc::new(Mutex::new(
        pcap_store::ring_buffer::PacketRingBuffer::new((config.pcap.ring_buffer_mb as usize) * 1024 * 1024)
    ));
    let pcap_captures = Arc::new(Mutex::new(VecDeque::new()));
    let pcap_output_dir = Arc::new(RwLock::new(std::path::PathBuf::from("pcap_data")));
    let pcap_seq = Arc::new(AtomicU64::new(1));
    let capture_enabled = Arc::new(AtomicBool::new(true));

    let app_state = Arc::new(AppState {
        metrics: metrics.clone(),
        flow_tracker: flow_tracker.clone(),
        ips_engine: ips_engine.clone(),
        sensor_name: config.sensor.name.clone(),
        capture_interface: capture_interface.clone(),
        capture_mode: format!("{:?}", config.capture.mode),
        config: Arc::new(RwLock::new(config.clone())),
        start_time,
        restart_capture: restart_capture.clone(),
        packet_ring: packet_ring.clone(),
        ips_event_ring: ips_event_ring.clone(),
        pcap_ring: pcap_ring.clone(),
        pcap_captures: pcap_captures.clone(),
        pcap_output_dir: pcap_output_dir.clone(),
        pcap_seq: pcap_seq.clone(),
        capture_enabled: capture_enabled.clone(),
    });

    // ── HTTP server ─────────────────────────────────────────────────
    let metrics_addr: std::net::SocketAddr = cli.metrics_addr.parse().context("invalid addr")?;
    info!(addr = %metrics_addr, "HTTP server starting (dashboard / + API /api/*)");

    let server_state = app_state.clone();
    tokio::spawn(async move {
        if let Err(e) = utils::logging::start_metrics_server(metrics_addr, server_state).await {
            error!(error = %e, "HTTP server error");
        }
    });

    // ── Flow eviction ───────────────────────────────────────────────
    let evict_tracker = flow_tracker.clone();
    let evict_metrics = metrics.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let (active, evicted) = {
                let mut t = evict_tracker.lock().unwrap();
                let e = t.evict_idle();
                let a = t.active_count();
                evict_metrics.active_flows.set(a as i64);
                (a, e.len())
            };
            if evicted > 0 { info!(evicted, active, "flow eviction"); }
        }
    });

    // ═══════════════════════════════════════════════════════════════════
    // ═══ LIVE CAPTURE PIPELINE (with runtime interface restart) ═════
    // ═══════════════════════════════════════════════════════════════════
    let cap_metrics = metrics.clone();
    let cap_flows = flow_tracker.clone();
    let cap_ips = ips_engine.clone();
    let cap_iface = capture_interface.clone();
    let cap_restart = restart_capture.clone();
    let cap_promisc = config.capture.promisc;
    let cap_snap_len = config.capture.snap_len;
    let cap_ring = packet_ring.clone();
    let cap_ips_events = ips_event_ring.clone();
    let cap_start = start_time;
    let cap_dissector_cfg = app_state.config.clone();
    let cap_state = app_state.clone();
    let cap_enabled = capture_enabled.clone();

    tokio::task::spawn_blocking(move || {
        loop {
            if !cap_enabled.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }

            let iface = cap_iface.read().unwrap().clone();
            info!(interface = %iface, "starting capture on interface");

            cap_restart.store(false, Ordering::SeqCst);

            let cap_config = CaptureConfig {
                interface: iface.clone(),
                promisc: cap_promisc,
                snap_len: cap_snap_len,
                timeout: Duration::from_millis(100),
            };

            let mut provider = match capture::create_provider(
                &crate::config::CaptureMode::Libpcap, cap_config,
            ) {
                Ok(p) => {
                    info!(backend = p.backend_name(), interface = p.interface(),
                          "✓ capture active — live traffic flowing");
                    p
                }
                Err(e) => {
                    warn!(error = %e, "capture failed — retrying in 3s. Try: sudo");
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };

            let mut pkt_count: u64 = 0;
            let mut last_log = Instant::now();

            loop {
                if !cap_enabled.load(Ordering::SeqCst) {
                    info!("capture paused by runtime toggle");
                    break;
                }

                // Check if we should restart on a new interface
                if cap_restart.load(Ordering::SeqCst) {
                    let new_iface = cap_iface.read().unwrap().clone();
                    info!(old = %iface, new = %new_iface, "interface switch requested — restarting capture");
                    break; // Outer loop will restart with new interface
                }

                match provider.next_packet() {
                    Ok(Some(packet)) => {
                        pkt_count += 1;

                        // Feed forensic PCAP ring from raw packet bytes.
                        cap_state.pcap_push_packet_bytes(&packet.data);

                        let meta = match dissectors::dissect_packet(&packet.data) {
                            Some(m) => m,
                            None => {
                                cap_metrics.packets_total
                                    .with_label_values(&[&iface, "malformed"]).inc();
                                continue;
                            }
                        };

                        // Check if this protocol's dissector is enabled
                        let proto = meta.protocol_name;
                        let is_enabled = {
                            let cfg = cap_dissector_cfg.read().unwrap();
                            match proto {
                                "tcp" | "tcp_truncated" => cfg.dissectors.tcp,
                                "udp" => cfg.dissectors.udp,
                                "icmp" => cfg.dissectors.icmp,
                                "dns" => cfg.dissectors.dns,
                                "http" => cfg.dissectors.http,
                                "tls" => cfg.dissectors.tls,
                                "ntp" => cfg.dissectors.ntp,
                                "dhcp" => cfg.dissectors.dhcp,
                                "modbus" => cfg.dissectors.modbus,
                                "dnp3" => cfg.dissectors.dnp3,
                                "bacnet" => cfg.dissectors.bacnet,
                                "enip" => cfg.dissectors.ethernet_ip,
                                "quic" => cfg.dissectors.udp, // QUIC is UDP-based
                                _ => true,
                            }
                        };

                        if !is_enabled {
                            continue;
                        }

                        cap_metrics.packets_total
                            .with_label_values(&[&iface, meta.protocol_name]).inc();

                        // Default verdict for packets without IP
                        let mut verdict = Verdict::Pass;
                        let mut rule_id = String::new();

                        if let (Some(src_ip), Some(dst_ip)) = (meta.src_ip, meta.dst_ip) {
                            let mut tracker = cap_flows.lock().unwrap();
                            tracker.update(
                                src_ip, dst_ip, meta.src_port, meta.dst_port,
                                meta.ip_proto, meta.payload_len as u16,
                                meta.tcp_flags, None,
                            );
                            let active = tracker.active_count();
                            cap_metrics.active_flows.set(active as i64);
                            drop(tracker);

                            let mut engine = cap_ips.lock().unwrap();
                            let (v, matched) = engine.evaluate(
                                Some(src_ip), Some(dst_ip),
                                meta.src_port, meta.dst_port,
                                meta.ip_proto, meta.tcp_flags, None, None,
                            );
                            verdict = v;

                            if let Some(rule) = matched {
                                rule_id = rule.id.clone();
                                cap_metrics.alerts_total
                                    .with_label_values(&[&rule.severity]).inc();

                                let elapsed = cap_start.elapsed().as_secs_f64();
                                cap_ips_events.lock().unwrap().push(IpsEventRecord {
                                    time_secs: elapsed,
                                    src_ip: src_ip.to_string(),
                                    dst_ip: dst_ip.to_string(),
                                    src_port: meta.src_port,
                                    dst_port: meta.dst_port,
                                    protocol: meta.protocol_name.to_uppercase(),
                                    verdict: format!("{:?}", verdict),
                                    rule_id: rule.id.clone(),
                                    severity: rule.severity.clone(),
                                    description: rule.description.clone(),
                                });

                                let five_tuple = format!(
                                    "{}:{} -> {}:{}/{}",
                                    src_ip,
                                    meta.src_port,
                                    dst_ip,
                                    meta.dst_port,
                                    meta.protocol_name.to_uppercase()
                                );
                                let trigger_mode = {
                                    let cfg = cap_state.config.read().unwrap();
                                    cfg.pcap.trigger.clone()
                                };
                                if trigger_mode.eq_ignore_ascii_case("alert") || trigger_mode.eq_ignore_ascii_case("always") {
                                    if let Err(e) = cap_state.create_pcap_capture("alert", &five_tuple, Some(&rule.id)) {
                                        warn!(error = %e, "failed to create alert-triggered PCAP capture");
                                    }
                                }

                                info!(rule = %rule.id, verdict = ?verdict,
                                      src = %src_ip, dst = %dst_ip, "⚠ IPS alert");
                            }
                        }

                        // Push packet into ring buffer for Packets tab
                        let elapsed = cap_start.elapsed().as_secs_f64();
                        let record = build_packet_record(
                            &meta, packet.info.orig_len, elapsed,
                            &verdict, &rule_id,
                        );
                        cap_ring.lock().unwrap().push(record);

                        if last_log.elapsed() >= Duration::from_secs(5) {
                            let flows = cap_flows.lock().unwrap().active_count();
                            info!(packets = pkt_count, flows, proto = meta.protocol_name,
                                  "capture stats");
                            last_log = Instant::now();
                        }
                    }
                    Ok(None) => {} // timeout
                    Err(e) => {
                        warn!(error = %e, "capture error");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
    });

    info!("ge-sensor ready → http://{}", metrics_addr);

    tokio::signal::ctrl_c().await.context("shutdown signal failed")?;
    info!("shutting down ge-sensor...");
    std::process::exit(0);
}
