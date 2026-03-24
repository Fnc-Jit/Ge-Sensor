//! Logging, tracing, and Prometheus observability for ge-sensor.
//!
//! Provides:
//! - Prometheus metrics registry with all 8 counters/gauges
//! - HTTP server serving dashboard, JSON API, metrics, and health

use anyhow::Result;
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use super::dashboard::AppState;

/// All Prometheus metrics for ge-sensor.
#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub packets_total: IntCounterVec,
    pub active_flows: IntGauge,
    pub kafka_lag: IntGauge,
    pub ram_usage_bytes: IntGauge,
    pub dlq_size_bytes: IntGauge,
    pub alerts_total: IntCounterVec,
    pub pcap_captures_total: IntCounter,
    pub kafka_delivery_errors_total: IntCounter,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let packets_total = IntCounterVec::new(
            Opts::new("ge_packets_total", "Total packets captured"),
            &["interface", "protocol"],
        )?;
        registry.register(Box::new(packets_total.clone()))?;

        let active_flows = IntGauge::new("ge_active_flows", "Active network flows")?;
        registry.register(Box::new(active_flows.clone()))?;

        let kafka_lag = IntGauge::new("ge_kafka_lag", "Kafka delivery lag")?;
        registry.register(Box::new(kafka_lag.clone()))?;

        let ram_usage_bytes = IntGauge::new("ge_ram_usage_bytes", "RSS memory bytes")?;
        registry.register(Box::new(ram_usage_bytes.clone()))?;

        let dlq_size_bytes = IntGauge::new("ge_dlq_size_bytes", "DLQ size bytes")?;
        registry.register(Box::new(dlq_size_bytes.clone()))?;

        let alerts_total = IntCounterVec::new(
            Opts::new("ge_alerts_total", "Total alerts fired"),
            &["severity"],
        )?;
        registry.register(Box::new(alerts_total.clone()))?;

        let pcap_captures_total = IntCounter::new("ge_pcap_captures_total", "PCAP captures")?;
        registry.register(Box::new(pcap_captures_total.clone()))?;

        let kafka_delivery_errors_total = IntCounter::new("ge_kafka_delivery_errors_total", "Kafka errors")?;
        registry.register(Box::new(kafka_delivery_errors_total.clone()))?;

        Ok(Self {
            registry, packets_total, active_flows, kafka_lag,
            ram_usage_bytes, dlq_size_bytes, alerts_total,
            pcap_captures_total, kafka_delivery_errors_total,
        })
    }

    pub fn encode(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

/// Start the HTTP server.
///
/// Endpoints:
/// - `GET /`                → Embedded dashboard
/// - `GET /api/state`       → Full sensor state JSON
/// - `GET /api/interfaces`  → List available capture interfaces
/// - `GET /api/set-interface?iface=<name>` → Switch capture interface
/// - `GET /metrics`         → Prometheus text
/// - `GET /health`          → JSON health
pub async fn start_metrics_server(
    addr: SocketAddr,
    app_state: Arc<AppState>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "HTTP server listening");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let state = app_state.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(n) if n > 0 => {
                    let request = String::from_utf8_lossy(&buf[..n]);

                    let (status, content_type, body) =
                        if request.contains("GET /api/set-interface") {
                            // Parse ?iface=<name> from the URL
                            let iface = request
                                .split("iface=")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .and_then(|s| s.split('&').next())
                                .and_then(|s| s.split(' ').next())
                                .unwrap_or("");

                            if iface.is_empty() {
                                ("400 Bad Request", "application/json",
                                 r#"{"error":"missing iface parameter"}"#.to_string())
                            } else if state.set_interface(iface) {
                                ("200 OK", "application/json",
                                 format!(r#"{{"ok":true,"interface":"{}"}}"#, iface))
                            } else {
                                ("404 Not Found", "application/json",
                                 format!(r#"{{"error":"interface '{}' not found"}}"#, iface))
                            }
                        } else if request.contains("GET /api/toggle-dissector") {
                            // Parse ?name=<name>&state=<true|false>
                            let qs = request.split('?').nth(1).and_then(|s| s.split_whitespace().next()).unwrap_or("");
                            let mut name = "";
                            let mut state_val = false;
                            
                            for pair in qs.split('&') {
                                let mut parts = pair.split('=');
                                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                                    if k == "name" { name = v; }
                                    if k == "state" { state_val = v == "true"; }
                                }
                            }
                            
                            if name.is_empty() {
                                ("400 Bad Request", "application/json", r#"{"error":"missing name parameter"}"#.to_string())
                            } else if state.toggle_dissector(name, state_val) {
                                ("200 OK", "application/json", format!(r#"{{"ok":true,"name":"{}","state":{}}}"#, name, state_val))
                            } else {
                                ("404 Not Found", "application/json", format!(r#"{{"error":"dissector '{}' not found"}}"#, name))
                            }
                        } else if request.contains("GET /api/packets") {
                            let packets = state.recent_packets();
                            match serde_json::to_string(&packets) {
                                Ok(json) => ("200 OK", "application/json", json),
                                Err(e) => ("500 Internal Server Error", "application/json",
                                           format!(r#"{{"error":"{}"}}"#, e)),
                            }
                        } else if request.contains("GET /api/interfaces") {
                            let interfaces = state.list_interfaces();
                            match serde_json::to_string(&interfaces) {
                                Ok(json) => ("200 OK", "application/json", json),
                                Err(e) => ("500 Internal Server Error", "application/json",
                                           format!(r#"{{"error":"{}"}}"#, e)),
                            }
                        } else if request.contains("GET /api/flows") {
                            let flows = state.flow_details();
                            match serde_json::to_string(&flows) {
                                Ok(json) => ("200 OK", "application/json", json),
                                Err(e) => ("500 Internal Server Error", "application/json",
                                           format!(r#"{{"error":"{}"}}"#, e)),
                            }
                        } else if request.contains("GET /api/config") {
                            match std::fs::read_to_string("configs/ge-sensor.yml") {
                                Ok(yaml) => {
                                    let json_val = serde_json::json!({"yaml": yaml});
                                    ("200 OK", "application/json", json_val.to_string())
                                }
                                Err(e) => ("500 Internal Server Error", "application/json", format!(r#"{{"error":"{}"}}"#, e)),
                            }
                        } else if request.starts_with("POST /api/config") {
                            // Extract payload from POST body
                            if let Some(body_start) = request.find("\r\n\r\n") {
                                let body = &request[body_start + 4..];
                                // Check if it's JSON {"yaml": "..."}
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                                    if let Some(yaml) = v.get("yaml").and_then(|y| y.as_str()) {
                                        if let Err(e) = std::fs::write("configs/ge-sensor.yml", yaml) {
                                            ("500 Internal Server Error", "application/json", format!(r#"{{"error":"{}"}}"#, e))
                                        } else {
                                            ("200 OK", "application/json", r#"{"ok":true}"#.to_string())
                                        }
                                    } else {
                                        ("400 Bad Request", "application/json", r#"{"error":"missing yaml field"}"#.to_string())
                                    }
                                } else {
                                    ("400 Bad Request", "application/json", r#"{"error":"invalid json body"}"#.to_string())
                                }
                            } else {
                                ("400 Bad Request", "application/json", r#"{"error":"missing body"}"#.to_string())
                            }

                        } else if request.contains("GET /api/state") {
                            let snapshot = state.snapshot();
                            match serde_json::to_string(&snapshot) {
                                Ok(json) => ("200 OK", "application/json", json),
                                Err(e) => ("500 Internal Server Error", "application/json",
                                           format!(r#"{{"error":"{}"}}"#, e)),
                            }
                        } else if request.contains("GET /metrics") {
                            match state.metrics.encode() {
                                Ok(body) => ("200 OK", "text/plain; version=0.0.4; charset=utf-8", body),
                                Err(e) => ("500 Internal Server Error", "text/plain",
                                           format!("metrics error: {e}")),
                            }
                        } else if request.contains("GET /health") {
                            let uptime = state.start_time.elapsed().as_secs();
                            let iface = state.capture_interface.read().unwrap().clone();
                            let health = format!(
                                r#"{{"status":"ok","sensor":"{}","version":"{}","uptime_secs":{},"interface":"{}"}}"#,
                                state.sensor_name, env!("CARGO_PKG_VERSION"), uptime, iface
                            );
                            ("200 OK", "application/json", health)
                        } else {
                            // Dashboard
                            ("200 OK", "text/html; charset=utf-8",
                             super::dashboard::DASHBOARD_HTML.to_string())
                        };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );

                    if let Err(e) = stream.write_all(response.as_bytes()).await {
                        warn!(peer = %peer, error = %e, "write failed");
                    }
                }
                _ => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new().expect("metrics should initialize");
        metrics.packets_total.with_label_values(&["eth0", "tcp"]).inc();
        metrics.active_flows.set(42);
        let output = metrics.encode().expect("should encode");
        assert!(output.contains("ge_packets_total"));
        assert!(output.contains("ge_active_flows 42"));
    }

    #[test]
    fn test_alerts_counter_labels() {
        let metrics = Metrics::new().unwrap();
        metrics.alerts_total.with_label_values(&["critical"]).inc_by(5);
        metrics.alerts_total.with_label_values(&["high"]).inc_by(3);
        let output = metrics.encode().unwrap();
        assert!(output.contains(r#"severity="critical"} 5"#));
        assert!(output.contains(r#"severity="high"} 3"#));
    }
}
