//! Dead-Letter Queue (DLQ) backed by local disk.
//!
//! When Kafka delivery fails, events are spooled to a local RocksDB-backed
//! storage with configurable size limits and circuit breaker logic.
//!
//! NOTE: RocksDB dependency is commented out in Cargo.toml for Phase 0-3.
//! This module provides a file-system-based fallback implementation.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// DLQ configuration.
#[derive(Debug, Clone)]
pub struct DlqConfig {
    /// Path to DLQ storage directory
    pub path: PathBuf,
    /// Maximum DLQ size in bytes
    pub max_bytes: u64,
    /// Retention period in days
    pub retention_days: u32,
    /// Circuit breaker threshold (0.0-1.0, fraction of max_bytes)
    pub circuit_breaker_threshold: f64,
}

impl Default for DlqConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/ge-sensor/dlq"),
            max_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            retention_days: 7,
            circuit_breaker_threshold: 0.80,
        }
    }
}

/// DLQ statistics.
#[derive(Debug, Default)]
pub struct DlqStats {
    /// Current size in bytes
    pub current_bytes: AtomicU64,
    /// Total events spooled
    pub total_spooled: AtomicU64,
    /// Total events replayed
    pub total_replayed: AtomicU64,
    /// Circuit breaker tripped
    pub circuit_open: AtomicBool,
}

/// Dead-Letter Queue implementation.
pub struct DeadLetterQueue {
    config: DlqConfig,
    stats: Arc<DlqStats>,
    sequence: AtomicU64,
}

impl DeadLetterQueue {
    /// Create a new DLQ, creating the storage directory if needed.
    pub fn new(config: DlqConfig) -> Result<Self> {
        fs::create_dir_all(&config.path).with_context(|| {
            format!("failed to create DLQ directory: {}", config.path.display())
        })?;

        // Calculate current size from existing files
        let current_bytes = Self::calculate_dir_size(&config.path);

        info!(
            path = %config.path.display(),
            max_gb = config.max_bytes / (1024 * 1024 * 1024),
            current_mb = current_bytes / (1024 * 1024),
            "DLQ initialized"
        );

        let stats = Arc::new(DlqStats::default());
        stats.current_bytes.store(current_bytes, Ordering::Relaxed);

        Ok(Self {
            config,
            stats,
            sequence: AtomicU64::new(0),
        })
    }

    /// Spool a failed event to the DLQ.
    pub fn spool(&self, payload: &[u8]) -> Result<()> {
        let current = self.stats.current_bytes.load(Ordering::Relaxed);
        let threshold = (self.config.max_bytes as f64 * self.config.circuit_breaker_threshold) as u64;

        // Circuit breaker check
        if current >= threshold {
            if !self.stats.circuit_open.load(Ordering::Relaxed) {
                self.stats.circuit_open.store(true, Ordering::Relaxed);
                warn!(
                    current_mb = current / (1024 * 1024),
                    threshold_mb = threshold / (1024 * 1024),
                    "DLQ circuit breaker OPEN — dropping low-priority events"
                );
            }
            return Ok(()); // Silently drop when circuit breaker is open
        }

        // Reset circuit breaker if below threshold
        if self.stats.circuit_open.load(Ordering::Relaxed) && current < threshold / 2 {
            self.stats.circuit_open.store(false, Ordering::Relaxed);
            info!("DLQ circuit breaker CLOSED — resuming spooling");
        }

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let filename = format!(
            "{}_{:016x}.ges",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            seq
        );
        let filepath = self.config.path.join(&filename);

        fs::write(&filepath, payload).with_context(|| {
            format!("failed to write DLQ event: {}", filepath.display())
        })?;

        self.stats
            .current_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        self.stats.total_spooled.fetch_add(1, Ordering::Relaxed);

        debug!(
            file = %filename,
            bytes = payload.len(),
            "event spooled to DLQ"
        );

        Ok(())
    }

    /// Get DLQ statistics.
    pub fn stats(&self) -> &Arc<DlqStats> {
        &self.stats
    }

    /// Get current DLQ size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.stats.current_bytes.load(Ordering::Relaxed)
    }

    /// Check if circuit breaker is open.
    pub fn is_circuit_open(&self) -> bool {
        self.stats.circuit_open.load(Ordering::Relaxed)
    }

    /// Calculate total size of files in a directory.
    fn calculate_dir_size(path: &Path) -> u64 {
        fs::read_dir(path)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_dlq_spool_and_stats() {
        let dir = tempdir().unwrap();
        let config = DlqConfig {
            path: dir.path().to_path_buf(),
            max_bytes: 1024 * 1024, // 1 MB
            retention_days: 7,
            circuit_breaker_threshold: 0.80,
        };

        let dlq = DeadLetterQueue::new(config).expect("should create DLQ");
        assert_eq!(dlq.size_bytes(), 0);
        assert!(!dlq.is_circuit_open());

        // Spool an event
        let payload = b"{\"@timestamp\":\"2026-03-24T00:00:00Z\",\"event.kind\":\"event\"}";
        dlq.spool(payload).expect("should spool");

        assert_eq!(dlq.stats().total_spooled.load(Ordering::Relaxed), 1);
        assert!(dlq.size_bytes() > 0);

        // Verify file was created
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1);
        assert!(files[0].file_name().to_string_lossy().ends_with(".ges"));
    }

    #[test]
    fn test_circuit_breaker() {
        let dir = tempdir().unwrap();
        let config = DlqConfig {
            path: dir.path().to_path_buf(),
            max_bytes: 100, // very small
            retention_days: 7,
            circuit_breaker_threshold: 0.50, // 50 bytes threshold
        };

        let dlq = DeadLetterQueue::new(config).expect("should create DLQ");

        // First spool: current=0 < threshold=50, so it writes (60 bytes)
        let big_payload = vec![b'X'; 60];
        dlq.spool(&big_payload).expect("first spool should succeed");
        assert_eq!(dlq.stats().total_spooled.load(Ordering::Relaxed), 1);

        // Second spool: current=60 >= threshold=50, so circuit breaker trips
        dlq.spool(&big_payload).expect("should not error");
        assert!(dlq.is_circuit_open(), "circuit breaker should be open now");

        // The second spool was dropped, so total_spooled stays at 1
        assert_eq!(dlq.stats().total_spooled.load(Ordering::Relaxed), 1);
    }
}
