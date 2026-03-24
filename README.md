<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.75+-orange?logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue" />
  <img src="https://img.shields.io/badge/License-Proprietary-red" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" />
</p>

# 🔱 ge-sensor

**High-performance network capture & IDS/IPS daemon for the God's Eye SIEM Platform.**

ge-sensor is a Rust-based network sensor that performs deep packet inspection, 5-tuple flow tracking with 14-feature ML extraction, protocol dissection, and inline/passive IPS — all from a single lightweight binary with an embedded real-time dashboard.

---

## ✨ Features

| Category | Details |
|---|---|
| **Packet Capture** | libpcap backend (af_packet & af_xdp planned), promiscuous mode, configurable snap length |
| **Flow Tracking** | 5-tuple bidirectional flows, LRU eviction, idle timeout, up to 100K concurrent flows |
| **ML Feature Extraction** | 14 features per flow — conn_rate, dns_entropy, beaconing_score, traffic_asymmetry, tcp_flag_anomaly, and more |
| **Protocol Dissectors** | TCP, UDP, ICMP, DNS, HTTP, TLS (JA3/JA4), NTP, DHCP, Modbus, DNP3, BACnet, EtherNet/IP |
| **IPS Engine** | Tap (passive) and Inline (active) modes with 5 built-in rules (SYN scan, XMAS, NULL, Modbus write, DNP3 control) |
| **Dashboard** | Embedded web UI at `:9090` with live stats, packet inspector, YAML config editor with syntax highlighting |
| **Metrics** | Prometheus-compatible `/metrics` endpoint |
| **Output** | Kafka producer (planned), Dead Letter Queue spool |

---

## 🏗 Architecture

```
ge-sensor/
├── src/
│   ├── main.rs              # Entry point, CLI, runtime orchestration
│   ├── config.rs             # YAML config parsing & validation
│   ├── capture/              # Packet capture backends (libpcap, af_packet, af_xdp)
│   ├── dissectors/           # Protocol dissectors (TCP, UDP, DNS, HTTP, TLS, OT protocols)
│   ├── flow/
│   │   ├── tracker.rs        # 5-tuple flow tracker with LRU eviction
│   │   └── features.rs       # 14-feature ML extraction per flow
│   ├── ips/                  # IDS/IPS engine (tap & inline modes)
│   ├── inputs/               # Syslog, SNMP Trap, NetFlow input listeners
│   ├── output/               # Kafka producer & DLQ
│   ├── pcap_store/           # Ring buffer PCAP storage
│   └── utils/
│       ├── dashboard.rs      # Dashboard state, API handlers
│       ├── dashboard.html    # Embedded single-file web UI
│       └── logging.rs        # HTTP server, metrics, API routing
├── configs/
│   └── ge-sensor.yml         # Production configuration
├── launch.sh                 # Interactive launcher script
└── Cargo.toml
```

---

## 🚀 Quick Start

### Prerequisites

- **Rust** ≥ 1.75 (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **libpcap** development headers
  - macOS: `brew install libpcap` (usually pre-installed)
  - Ubuntu/Debian: `sudo apt install libpcap-dev`
  - RHEL/Fedora: `sudo dnf install libpcap-devel`

### Build & Run

```bash
# Clone
git clone https://github.com/Fnc-Jit/Ge-Sensor.git
cd Ge-Sensor

# Interactive launch (builds automatically, prompts for interface)
sudo ./launch.sh
```

The launcher will:
1. List all available network interfaces
2. Prompt you to select one (defaults to the active Wi-Fi/Ethernet interface)
3. Build the project via `cargo build`
4. Start the sensor with packet capture

### Manual Build

```bash
cargo build --release
sudo ./target/release/ge-sensor --config configs/ge-sensor.yml --interface en0
```

> **Note:** `sudo` is required for raw packet capture (promiscuous mode).

---

## 🖥 Dashboard

Once running, open **http://localhost:9090** in your browser.

### Tabs

| Tab | Description |
|---|---|
| **Overview** | Live stat cards, packet throughput bar chart, runtime config panel |
| **Flow Tracker** | 5 stat cards (Total/TCP/UDP/Anomalous/Avg Duration), anomalous flows table with ML scores, 14 ML feature definitions |
| **Dissectors** | Toggle protocol dissectors on/off in real-time |
| **Packets** | Wireshark-style live packet inspector with hex dump |
| **IPS** | IPS engine stats, rule list, mode display |
| **Logs** | Live log stream from the sensor |
| **Inputs** | Syslog, SNMP Trap, NetFlow listener status |
| **Kafka** | Output broker status, topic, lag, delivery errors |
| **Configuration** | YAML config editor with syntax highlighting, save & apply, download |

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard HTML |
| `/api/state` | GET | Full sensor state (JSON) |
| `/api/flows` | GET | Per-flow data with ML features (JSON) |
| `/api/packets` | GET | Recent captured packets (JSON) |
| `/api/config` | GET | Current YAML configuration |
| `/api/config` | POST | Update & apply configuration |
| `/api/interfaces` | GET | Available network interfaces |
| `/api/set-interface?name=` | GET | Switch capture interface |
| `/api/toggle-dissector?name=&state=` | GET | Toggle dissector on/off |
| `/metrics` | GET | Prometheus metrics |
| `/health` | GET | Health check |

---

## 🧠 ML Feature Extraction

Each tracked flow has a **14-element feature vector** extracted in real-time:

| # | Feature | Type | Description |
|---|---|---|---|
| 01 | `conn_rate` | Behavioral | Connection attempts/min from source |
| 02 | `unique_dst` | Behavioral | Unique destination IPs contacted |
| 03 | `dns_entropy` | Network | Shannon entropy of DNS query hostnames |
| 04 | `beaconing_score` | Behavioral | Regularity of connection intervals (C2 indicator) |
| 05 | `traffic_asymmetry` | Network | Upload vs download byte ratio deviation |
| 06 | `off_hours_pct` | Temporal | % of traffic outside business hours |
| 07 | `iat_mean` | Network | Mean inter-arrival time between packets |
| 08 | `bytes_ratio` | Network | Bytes per packet ratio |
| 09 | `protocol_entropy` | Behavioral | Diversity of protocols used |
| 10 | `port_entropy` | Behavioral | Diversity of destination ports |
| 11 | `packet_size_var` | Network | Variance in packet sizes |
| 12 | `tcp_flag_anomaly` | Network | Unusual TCP flag combinations |
| 13 | `payload_entropy` | Network | Shannon entropy of payload bytes |
| 14 | `geo_distance` | Temporal | Geographic distance from baseline |

A composite **ML Anomaly Score** (0.0–1.0) is computed as a weighted combination of these features.

---

## ⚙️ Configuration

Configuration is managed via `configs/ge-sensor.yml`:

```yaml
sensor:
  name: "ge-sensor-01"
  environment: "production"
  log_level: "info"

capture:
  interface: "en0"
  mode: "af_packet"        # af_packet | af_xdp | libpcap
  promisc: true
  snap_len: 65535

dissectors:
  tcp: true
  udp: true
  dns: true
  http: true
  tls: true
  modbus: true
  dnp3: true

ips:
  enabled: false
  mode: "inline"           # inline | tap
  default_action: "pass"
```

Configuration can be edited live via the dashboard's **Configuration** tab with full YAML syntax highlighting.

---

## 🔒 IPS Rules (Built-in)

| Rule ID | Description | Action | Severity |
|---|---|---|---|
| `GE-NET-001` | SYN scan on port 0 (reconnaissance) | Drop | High |
| `GE-NET-002` | XMAS tree scan detected | Drop | High |
| `GE-NET-003` | NULL scan detected (no TCP flags) | Alert | Medium |
| `GE-OT-001` | Unauthorized Modbus write operation | Drop | Critical |
| `GE-OT-002` | Unauthorized DNP3 control command | Drop | Critical |

---

## 📊 Prometheus Metrics

Available at `http://localhost:9090/metrics`:

- `ge_packets_total` — Total packets captured
- `ge_bytes_total` — Total bytes captured
- `ge_active_flows` — Current active flow count
- `ge_kafka_lag` — Kafka delivery lag
- `ge_kafka_delivery_errors_total` — Kafka delivery failures
- `ge_dlq_size_bytes` — Dead letter queue size
- `ge_ram_usage_bytes` — Process RSS memory
- `ge_ips_*` — IPS engine counters

---

## 🛠 Development

```bash
# Run tests
cargo test

# Build with specific features
cargo build --features "af_packet,ips_inline"

# Release build (optimized, stripped)
cargo build --release
```

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `libpcap_capture` | ✅ | libpcap-based packet capture |
| `af_packet` | ❌ | Linux AF_PACKET capture (planned) |
| `af_xdp` | ❌ | Linux AF_XDP/eBPF capture (planned) |
| `ips_inline` | ❌ | Inline IPS with nfqueue (planned) |

---

## 🗺 Roadmap

- [x] Core packet capture (libpcap)
- [x] Protocol dissectors (TCP, UDP, DNS, HTTP, TLS, OT)
- [x] 5-tuple flow tracking with LRU eviction
- [x] 14-feature ML extraction per flow
- [x] IPS engine (tap mode)
- [x] Embedded dashboard with live updates
- [x] YAML config editor with syntax highlighting
- [x] Prometheus metrics
- [ ] AF_PACKET / AF_XDP capture backends
- [ ] Kafka producer integration
- [ ] RocksDB dead-letter queue
- [ ] PCAP ring buffer storage
- [ ] Inline IPS with nfqueue
- [ ] TLS certificate pinning & mTLS
- [ ] ge-agent integration for centralized management

---

## 📄 License

Proprietary — God's Eye Platform. All rights reserved.
