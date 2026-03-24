//! Configuration module for ge-sensor.
//!
//! Loads and validates the YAML configuration file. All config structs
//! are strongly typed with serde deserialization and validator constraints.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use validator::Validate;

/// Top-level sensor configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct Config {
    pub sensor: SensorConfig,
    pub capture: CaptureConfig,
    #[serde(default)]
    pub dissectors: DissectorConfig,
    #[serde(default)]
    pub pcap: PcapConfig,
    #[serde(default)]
    pub ips: IpsConfig,
    #[serde(default)]
    pub inputs: InputsConfig,
    pub output: OutputConfig,
}

/// Core sensor identity and runtime settings.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SensorConfig {
    /// Unique sensor name (e.g., "ge-sensor-01")
    #[validate(length(min = 1, message = "sensor name must not be empty"))]
    pub name: String,

    /// Deployment environment tag
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Logging verbosity: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Tenant UUID for multi-tenant isolation
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Capture interface configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CaptureConfig {
    /// Network interface name (e.g., "eth0")
    #[validate(length(min = 1, message = "capture interface must not be empty"))]
    pub interface: String,

    /// Capture mode: "libpcap", "af_packet", "af_xdp"
    #[serde(default = "default_capture_mode")]
    pub mode: CaptureMode,

    /// Enable promiscuous mode
    #[serde(default = "default_true")]
    pub promisc: bool,

    /// Snapshot length in bytes (max bytes per packet)
    #[serde(default = "default_snap_len")]
    #[validate(range(min = 64, max = 65535, message = "snap_len must be 64..65535"))]
    pub snap_len: u32,
}

/// Supported capture modes.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    Libpcap,
    AfPacket,
    AfXdp,
}

/// Protocol dissector toggle flags.
#[derive(Debug, Clone, Deserialize)]
pub struct DissectorConfig {
    #[serde(default = "default_true")]
    pub tcp: bool,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default = "default_true")]
    pub icmp: bool,
    #[serde(default = "default_true")]
    pub dns: bool,
    #[serde(default = "default_true")]
    pub http: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default = "default_true")]
    pub ntp: bool,
    #[serde(default = "default_true")]
    pub dhcp: bool,
    #[serde(default)]
    pub modbus: bool,
    #[serde(default)]
    pub dnp3: bool,
    #[serde(default)]
    pub bacnet: bool,
    #[serde(default)]
    pub ethernet_ip: bool,
}

/// Selective PCAP configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PcapConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Trigger mode: "alert", "always", "off"
    #[serde(default = "default_pcap_trigger")]
    pub trigger: String,

    /// Ring buffer size in megabytes
    #[serde(default = "default_ring_buffer_mb")]
    pub ring_buffer_mb: u32,

    /// Days to retain triggered PCAP files
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

/// IPS inline blocking configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct IpsConfig {
    #[serde(default)]
    pub enabled: bool,

    /// IPS mode: "inline" or "tap"
    #[serde(default = "default_ips_mode")]
    pub mode: String,

    /// Default action when no rule matches: "pass" or "drop"
    #[serde(default = "default_ips_action")]
    pub default_action: String,
}

/// Auxiliary input source configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct InputsConfig {
    #[serde(default)]
    pub syslog: Option<ListenerConfig>,
    #[serde(default)]
    pub netflow: Option<ListenerConfig>,
    #[serde(default)]
    pub snmp: Option<ListenerConfig>,
    #[serde(default)]
    pub ipfix: Option<ListenerConfig>,
    /// Windows Event Forwarding (WEF) / WEC collector
    #[serde(default)]
    pub wef: Option<ListenerConfig>,
    /// HTTP webhook receiver (JSON logs, cloud alerts, etc.)
    #[serde(default)]
    pub http_webhook: Option<ListenerConfig>,
}

/// Generic UDP/TCP listener configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ListenerConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Protocol: "udp" or "tcp"
    #[serde(default = "default_udp")]
    pub protocol: String,

    /// Bind address
    #[serde(default = "default_bind_addr")]
    pub host: String,

    /// Bind port
    pub port: u16,
}

/// Output pipeline configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct OutputConfig {
    pub kafka: KafkaConfig,
    #[serde(default)]
    pub dlq: Option<DlqConfig>,
}

/// Kafka producer configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct KafkaConfig {
    /// Broker addresses
    #[validate(length(min = 1, message = "at least one Kafka broker is required"))]
    pub brokers: Vec<String>,

    /// Target topic name
    #[serde(default = "default_kafka_topic")]
    pub topic: String,

    /// mTLS settings
    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
}

/// mTLS certificate configuration for Kafka.
#[derive(Debug, Clone, Deserialize)]
pub struct MtlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub ca: Option<PathBuf>,
}

/// Dead-letter queue (RocksDB) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DlqConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Path to DLQ storage directory
    #[serde(default = "default_dlq_path")]
    pub path: PathBuf,

    /// Maximum DLQ size in gigabytes
    #[serde(default = "default_dlq_max_gb")]
    pub max_gb: u32,

    /// Retention period in days
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

// ── Default value functions ──────────────────────────────────────────────

fn default_environment() -> String {
    "production".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_capture_mode() -> CaptureMode {
    CaptureMode::Libpcap
}
fn default_true() -> bool {
    true
}
fn default_snap_len() -> u32 {
    65535
}
fn default_pcap_trigger() -> String {
    "alert".into()
}
fn default_ring_buffer_mb() -> u32 {
    512
}
fn default_retention_days() -> u32 {
    7
}
fn default_ips_mode() -> String {
    "tap".into()
}
fn default_ips_action() -> String {
    "pass".into()
}
fn default_udp() -> String {
    "udp".into()
}
fn default_bind_addr() -> String {
    "0.0.0.0".into()
}
fn default_kafka_topic() -> String {
    "ge.raw.logs".into()
}
fn default_dlq_path() -> PathBuf {
    PathBuf::from("/var/lib/ge-sensor/dlq")
}
fn default_dlq_max_gb() -> u32 {
    10
}

// ── Default impls ────────────────────────────────────────────────────────

impl Default for DissectorConfig {
    fn default() -> Self {
        Self {
            tcp: true,
            udp: true,
            icmp: true,
            dns: true,
            http: true,
            tls: true,
            ntp: true,
            dhcp: true,
            modbus: false,
            dnp3: false,
            bacnet: false,
            ethernet_ip: false,
        }
    }
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trigger: default_pcap_trigger(),
            ring_buffer_mb: default_ring_buffer_mb(),
            retention_days: default_retention_days(),
        }
    }
}

impl Default for IpsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_ips_mode(),
            default_action: default_ips_action(),
        }
    }
}

// ── Config loader ────────────────────────────────────────────────────────

impl Config {
    /// Load and validate configuration from a YAML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let config: Config = serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse YAML config: {}", path.display()))?;

        // Run validator constraints
        config
            .sensor
            .validate()
            .context("sensor config validation failed")?;
        config
            .capture
            .validate()
            .context("capture config validation failed")?;
        config
            .output
            .kafka
            .validate()
            .context("kafka config validation failed")?;

        // Validate capture mode vs platform
        #[cfg(not(target_os = "linux"))]
        {
            if config.capture.mode == CaptureMode::AfPacket {
                tracing::warn!(
                    "AF_PACKET capture mode is Linux-only; falling back to libpcap"
                );
            }
            if config.capture.mode == CaptureMode::AfXdp {
                tracing::warn!(
                    "AF_XDP capture mode is Linux-only; falling back to libpcap"
                );
            }
        }

        tracing::info!(
            sensor = %config.sensor.name,
            interface = %config.capture.interface,
            mode = ?config.capture.mode,
            "configuration loaded successfully"
        );

        Ok(config)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config_parse() {
        let yaml = r#"
sensor:
  name: ge-sensor-01
  environment: production
  log_level: info

capture:
  interface: eth0
  mode: libpcap
  promisc: true
  snap_len: 65535

output:
  kafka:
    brokers: ["kafka-1:9092"]
    topic: ge.raw.logs
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sensor.name, "ge-sensor-01");
        assert_eq!(config.capture.interface, "eth0");
        assert_eq!(config.capture.mode, CaptureMode::Libpcap);
        assert!(config.capture.promisc);
        assert_eq!(config.capture.snap_len, 65535);
        assert_eq!(config.output.kafka.brokers.len(), 1);
    }

    #[test]
    fn test_invalid_snap_len_rejected() {
        let yaml = r#"
sensor:
  name: test
capture:
  interface: eth0
  snap_len: 10
output:
  kafka:
    brokers: ["broker:9092"]
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let result = config.capture.validate();
        assert!(result.is_err(), "snap_len=10 should fail validation");
    }

    #[test]
    fn test_empty_sensor_name_rejected() {
        let yaml = r#"
sensor:
  name: ""
capture:
  interface: eth0
output:
  kafka:
    brokers: ["broker:9092"]
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let result = config.sensor.validate();
        assert!(result.is_err(), "empty sensor name should fail validation");
    }

    #[test]
    fn test_default_dissectors() {
        let d = DissectorConfig::default();
        assert!(d.tcp);
        assert!(d.udp);
        assert!(d.dns);
        assert!(!d.modbus);
        assert!(!d.dnp3);
    }
}
