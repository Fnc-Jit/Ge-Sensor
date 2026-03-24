//! Flow tracking module for ge-sensor.
//!
//! Tracks network sessions using 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
//! with HashMap storage and LRU eviction at configurable capacity limits.

pub mod tracker;
pub mod features;
