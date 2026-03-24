//! 14-Feature ML extraction per flow.
//!
//! Computes the dense `[f32; 14]` feature array from a FlowRecord
//! for injection into the ML pipeline via Kafka.
//!
//! Features match the spec exactly:
//! 1. conn_rate          7. iat_mean           13. payload_entropy
//! 2. unique_dst         8. bytes_ratio        14. geo_distance (stub=0.0)
//! 3. dns_entropy        9. protocol_entropy
//! 4. beaconing_score   10. port_entropy
//! 5. traffic_asymmetry 11. packet_size_var
//! 6. off_hours_pct     12. tcp_flag_anomaly

use super::tracker::FlowRecord;
use std::time::Duration;

/// Feature indices for the 14-element array.
pub mod idx {
    pub const CONN_RATE: usize = 0;
    pub const UNIQUE_DST: usize = 1;
    pub const DNS_ENTROPY: usize = 2;
    pub const BEACONING_SCORE: usize = 3;
    pub const TRAFFIC_ASYMMETRY: usize = 4;
    pub const OFF_HOURS_PCT: usize = 5;
    pub const IAT_MEAN: usize = 6;
    pub const BYTES_RATIO: usize = 7;
    pub const PROTOCOL_ENTROPY: usize = 8;
    pub const PORT_ENTROPY: usize = 9;
    pub const PACKET_SIZE_VAR: usize = 10;
    pub const TCP_FLAG_ANOMALY: usize = 11;
    pub const PAYLOAD_ENTROPY: usize = 12;
    pub const GEO_DISTANCE: usize = 13;
}

/// Extract the 14-element ML feature array from a flow record.
pub fn extract_features(record: &FlowRecord) -> [f32; 14] {
    let mut features = [0.0f32; 14];

    let total_packets = record.fwd_packets + record.rev_packets;
    let total_bytes = record.fwd_bytes + record.rev_bytes;
    let duration = record.last_seen.duration_since(record.first_seen);
    let duration_secs = duration.as_secs_f32().max(0.001); // avoid div-by-zero

    // 1. conn_rate: packets per second
    features[idx::CONN_RATE] = total_packets as f32 / duration_secs;

    // 2. unique_dst: stub — 1.0 for this single flow (enrichment layer populates globally)
    features[idx::UNIQUE_DST] = 1.0;

    // 3. dns_entropy: Shannon entropy of DNS query characters
    features[idx::DNS_ENTROPY] = compute_dns_entropy(&record.dns_queries);

    // 4. beaconing_score: regularity of inter-arrival times (low stddev/mean = beaconing)
    features[idx::BEACONING_SCORE] = compute_beaconing_score(&record.inter_arrival_times);

    // 5. traffic_asymmetry: ratio of fwd vs rev bytes
    if total_bytes > 0 {
        features[idx::TRAFFIC_ASYMMETRY] =
            (record.fwd_bytes as f32 - record.rev_bytes as f32).abs() / total_bytes as f32;
    }

    // 6. off_hours_pct: stub — requires wall-clock business hours config (populated at L4)
    features[idx::OFF_HOURS_PCT] = 0.0;

    // 7. iat_mean: mean inter-arrival time in milliseconds
    features[idx::IAT_MEAN] = compute_iat_mean(&record.inter_arrival_times);

    // 8. bytes_ratio: total bytes / total packets
    if total_packets > 0 {
        features[idx::BYTES_RATIO] = total_bytes as f32 / total_packets as f32;
    }

    // 9. protocol_entropy: stub — requires cross-flow analysis (populated at enrichment)
    features[idx::PROTOCOL_ENTROPY] = 0.0;

    // 10. port_entropy: stub — requires cross-flow analysis
    features[idx::PORT_ENTROPY] = 0.0;

    // 11. packet_size_var: variance of packet sizes
    features[idx::PACKET_SIZE_VAR] = compute_variance(&record.packet_sizes);

    // 12. tcp_flag_anomaly: detect abnormal flag combinations
    features[idx::TCP_FLAG_ANOMALY] = compute_tcp_flag_anomaly(record.tcp_flags_union);

    // 13. payload_entropy: stub — requires payload bytes (will be populated by dissector)
    features[idx::PAYLOAD_ENTROPY] = 0.0;

    // 14. geo_distance: stub — always 0.0, populated by enrichment layer L4
    features[idx::GEO_DISTANCE] = 0.0;

    features
}

/// Shannon entropy of concatenated DNS query names.
fn compute_dns_entropy(queries: &[String]) -> f32 {
    if queries.is_empty() {
        return 0.0;
    }

    let combined: String = queries.join("");
    if combined.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in combined.as_bytes() {
        freq[b as usize] += 1;
    }

    let total = combined.len() as f32;
    let mut entropy = 0.0f32;

    for &count in freq.iter() {
        if count > 0 {
            let p = count as f32 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Beaconing score: coefficient of variation of inter-arrival times.
/// Low CV (< 0.2) indicates regular beaconing behavior → high score.
fn compute_beaconing_score(iats: &[Duration]) -> f32 {
    if iats.len() < 2 {
        return 0.0;
    }

    let values: Vec<f32> = iats.iter().map(|d| d.as_secs_f32() * 1000.0).collect();
    let mean = values.iter().sum::<f32>() / values.len() as f32;

    if mean < 0.001 {
        return 0.0;
    }

    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f32>() / values.len() as f32;
    let stddev = variance.sqrt();
    let cv = stddev / mean;

    // Convert CV to beaconing score: lower CV = higher beaconing score
    // CV < 0.1 → score ~1.0; CV > 1.0 → score ~0.0
    (1.0 - cv.min(1.0)).max(0.0)
}

/// Mean inter-arrival time in milliseconds.
fn compute_iat_mean(iats: &[Duration]) -> f32 {
    if iats.is_empty() {
        return 0.0;
    }
    let total_ms: f32 = iats.iter().map(|d| d.as_secs_f32() * 1000.0).sum();
    total_ms / iats.len() as f32
}

/// Variance of packet sizes.
fn compute_variance(sizes: &[u16]) -> f32 {
    if sizes.len() < 2 {
        return 0.0;
    }
    let mean = sizes.iter().map(|&s| s as f32).sum::<f32>() / sizes.len() as f32;
    sizes
        .iter()
        .map(|&s| (s as f32 - mean).powi(2))
        .sum::<f32>()
        / sizes.len() as f32
}

/// Detect TCP flag anomalies.
/// Returns a float score: 0.0 = normal, higher = more anomalous.
fn compute_tcp_flag_anomaly(flags_union: u8) -> f32 {
    use crate::dissectors::tcp_flags;

    let mut score = 0.0f32;

    // SYN + FIN is abnormal (used in port scanning)
    if flags_union & tcp_flags::SYN != 0 && flags_union & tcp_flags::FIN != 0 {
        score += 0.5;
    }

    // XMAS tree scan: FIN + PSH + URG
    if flags_union & tcp_flags::FIN != 0
        && flags_union & tcp_flags::PSH != 0
        && flags_union & tcp_flags::URG != 0
    {
        score += 0.5;
    }

    // NULL scan: no flags at all (unlikely in normal traffic if TCP)
    if flags_union == 0 {
        score += 0.3;
    }

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::tracker::{FlowKey, FlowRecord};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn make_flow() -> FlowRecord {
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };
        let mut record = FlowRecord {
            key,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            fwd_packets: 100,
            rev_packets: 50,
            fwd_bytes: 150_000,
            rev_bytes: 50_000,
            inter_arrival_times: vec![Duration::from_millis(10); 20],
            packet_sizes: vec![1500, 64, 1200, 800, 500, 300],
            tcp_flags_union: 0x12, // SYN-ACK (normal)
            dns_queries: vec!["example.com".into()],
        };
        // Set last_seen 10 seconds after first_seen
        record.last_seen = record.first_seen + Duration::from_secs(10);
        record
    }

    #[test]
    fn test_feature_extraction() {
        let record = make_flow();
        let features = extract_features(&record);

        // conn_rate: 150 packets / 10 sec = 15.0
        assert!((features[idx::CONN_RATE] - 15.0).abs() < 0.1);

        // unique_dst = 1.0 (stub)
        assert_eq!(features[idx::UNIQUE_DST], 1.0);

        // dns_entropy > 0 (has query)
        assert!(features[idx::DNS_ENTROPY] > 0.0);

        // traffic_asymmetry: |150000 - 50000| / 200000 = 0.5
        assert!((features[idx::TRAFFIC_ASYMMETRY] - 0.5).abs() < 0.01);

        // iat_mean: 10ms
        assert!((features[idx::IAT_MEAN] - 10.0).abs() < 0.1);

        // bytes_ratio: 200000 / 150 ≈ 1333.33
        assert!((features[idx::BYTES_RATIO] - 1333.33).abs() < 1.0);

        // tcp_flag_anomaly: SYN-ACK is normal → 0.0
        assert_eq!(features[idx::TCP_FLAG_ANOMALY], 0.0);

        // geo_distance: stub = 0.0
        assert_eq!(features[idx::GEO_DISTANCE], 0.0);
    }

    #[test]
    fn test_xmas_scan_detection() {
        use crate::dissectors::tcp_flags;
        let anomaly = compute_tcp_flag_anomaly(
            tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG | tcp_flags::SYN,
        );
        assert!(anomaly >= 0.9, "XMAS + SYN should be highly anomalous");
    }

    #[test]
    fn test_beaconing_score_regular() {
        // Regular 100ms intervals → high beaconing score
        let iats: Vec<Duration> = (0..20).map(|_| Duration::from_millis(100)).collect();
        let score = compute_beaconing_score(&iats);
        assert!(score > 0.9, "regular intervals should score high: {score}");
    }

    #[test]
    fn test_beaconing_score_random() {
        // Random intervals → low beaconing score
        let iats: Vec<Duration> = vec![
            Duration::from_millis(10),
            Duration::from_millis(500),
            Duration::from_millis(20),
            Duration::from_millis(1000),
            Duration::from_millis(5),
        ];
        let score = compute_beaconing_score(&iats);
        assert!(score < 0.5, "random intervals should score low: {score}");
    }
}
