//! Kafka producer for ge-sensor.
//!
//! Delivers GES-formatted JSON events to the `ge.raw.logs` Kafka topic.
//! Uses rdkafka (librdkafka wrapper) with mTLS support.
//!
//! NOTE: rdkafka dependency is commented out in Cargo.toml for Phase 0-3.
//! This module provides the interface and a mock implementation for testing.
//! Uncomment `rdkafka` in Cargo.toml to enable real Kafka delivery.

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use super::GesEvent;

/// Kafka producer configuration.
#[derive(Debug, Clone)]
pub struct KafkaProducerConfig {
    /// Broker addresses (comma-separated or vec)
    pub brokers: Vec<String>,
    /// Target topic name
    pub topic: String,
    /// mTLS certificate path
    pub cert_path: Option<String>,
    /// mTLS key path
    pub key_path: Option<String>,
    /// mTLS CA path
    pub ca_path: Option<String>,
    /// Batch size in bytes
    pub batch_size: usize,
    /// Linger time in milliseconds
    pub linger_ms: u64,
}

impl Default for KafkaProducerConfig {
    fn default() -> Self {
        Self {
            brokers: vec!["localhost:9092".into()],
            topic: "ge.raw.logs".into(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            batch_size: 65536,
            linger_ms: 5,
        }
    }
}

/// Kafka delivery statistics.
#[derive(Debug, Default)]
pub struct DeliveryStats {
    /// Total events successfully delivered
    pub delivered: AtomicU64,
    /// Total delivery errors
    pub errors: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
}

/// Kafka producer interface.
/// When rdkafka is available, this wraps FutureProducer.
/// Otherwise, provides a mock/logging implementation.
pub struct GeSensorKafkaProducer {
    config: KafkaProducerConfig,
    stats: Arc<DeliveryStats>,
}

impl GeSensorKafkaProducer {
    /// Create a new Kafka producer.
    pub fn new(config: KafkaProducerConfig) -> Result<Self> {
        info!(
            brokers = ?config.brokers,
            topic = %config.topic,
            batch_size = config.batch_size,
            linger_ms = config.linger_ms,
            "Kafka producer initialized"
        );

        // When rdkafka is available, this would create:
        // let producer: FutureProducer = ClientConfig::new()
        //     .set("bootstrap.servers", &config.brokers.join(","))
        //     .set("batch.size", &config.batch_size.to_string())
        //     .set("linger.ms", &config.linger_ms.to_string())
        //     .set("acks", "all")
        //     .set("ssl.ca.location", ca_path)
        //     .set("ssl.certificate.location", cert_path)
        //     .set("ssl.key.location", key_path)
        //     .create()?;

        Ok(Self {
            config,
            stats: Arc::new(DeliveryStats::default()),
        })
    }

    /// Send a GES event to Kafka.
    pub async fn send(&self, event: &GesEvent) -> Result<()> {
        let payload = serde_json::to_vec(event)
            .context("failed to serialize GES event to JSON")?;

        let payload_len = payload.len() as u64;

        // When rdkafka is available:
        // let record = FutureRecord::to(&self.config.topic)
        //     .payload(&payload)
        //     .key(&event.source_ip);
        // match self.producer.send(record, Duration::from_secs(5)).await {
        //     Ok(_) => { stats... }
        //     Err((e, _)) => { dlq... }
        // }

        // Mock: log and count
        debug!(
            topic = %self.config.topic,
            bytes = payload_len,
            protocol = %event.network_protocol,
            "event delivered to Kafka"
        );

        self.stats.delivered.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(payload_len, Ordering::Relaxed);

        Ok(())
    }

    /// Get delivery statistics.
    pub fn stats(&self) -> &Arc<DeliveryStats> {
        &self.stats
    }

    /// Get the target topic name.
    pub fn topic(&self) -> &str {
        &self.config.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_kafka_producer_send() {
        let producer = GeSensorKafkaProducer::new(KafkaProducerConfig::default())
            .expect("should create producer");

        let event = GesEvent::from_packet(
            "tcp",
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            1234,
            80,
            "test-tenant",
            None,
        );

        producer.send(&event).await.expect("should send");
        assert_eq!(producer.stats().delivered.load(Ordering::Relaxed), 1);
        assert!(producer.stats().bytes_sent.load(Ordering::Relaxed) > 0);
    }
}
