//! IPS (Intrusion Prevention System) inline engine for ge-sensor.
//!
//! Provides packet filtering and inline blocking based on configurable rules.
//! In "inline" mode, the engine applies drop/pass verdicts to each packet.
//! In "tap" mode (default), it only generates alerts without blocking.
//!
//! NOTE: Inline dropping requires Linux nfqueue or AF_PACKET TX injection.
//! This module provides the rule matching engine and verdict logic.

use std::net::IpAddr;
use tracing::{debug, info, warn};

/// IPS verdicts for each packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allow the packet through
    Pass,
    /// Drop the packet (inline mode only)
    Drop,
    /// Alert but pass the packet
    Alert,
}

/// IPS operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsMode {
    /// Monitor only, no blocking
    Tap,
    /// Active inline blocking
    Inline,
}

/// An IPS rule for matching packets.
#[derive(Debug, Clone)]
pub struct IpsRule {
    /// Unique rule identifier (e.g., "GE-2024-001")
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Severity: critical, high, medium, low
    pub severity: String,
    /// Action to take on match
    pub action: Verdict,
    /// Match criteria
    pub criteria: RuleCriteria,
    /// Is this rule enabled?
    pub enabled: bool,
}

/// Criteria for matching a packet against a rule.
#[derive(Debug, Clone, Default)]
pub struct RuleCriteria {
    /// Source IP match (None = any)
    pub src_ip: Option<IpAddr>,
    /// Destination IP match (None = any)
    pub dst_ip: Option<IpAddr>,
    /// Source port match (None = any)
    pub src_port: Option<u16>,
    /// Destination port match (None = any)
    pub dst_port: Option<u16>,
    /// Protocol match (None = any)
    pub protocol: Option<u8>,
    /// TCP flags mask (None = any)
    pub tcp_flags_mask: Option<u8>,
    /// TCP flags value (matched after mask)
    pub tcp_flags_value: Option<u8>,
    /// OT: Modbus function codes to block
    pub modbus_func_codes: Vec<u8>,
    /// OT: DNP3 function codes to block
    pub dnp3_func_codes: Vec<u8>,
}

/// IPS engine statistics.
#[derive(Debug, Default)]
pub struct IpsStats {
    pub packets_inspected: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_alerted: u64,
    pub rules_matched: u64,
}

/// The main IPS engine.
pub struct IpsEngine {
    mode: IpsMode,
    rules: Vec<IpsRule>,
    default_action: Verdict,
    stats: IpsStats,
}

impl IpsEngine {
    /// Create a new IPS engine.
    pub fn new(mode: IpsMode, default_action: Verdict) -> Self {
        info!(
            mode = ?mode,
            default_action = ?default_action,
            "IPS engine initialized"
        );

        Self {
            mode,
            rules: Vec::new(),
            default_action,
            stats: IpsStats::default(),
        }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: IpsRule) {
        info!(
            rule_id = %rule.id,
            action = ?rule.action,
            severity = %rule.severity,
            "IPS rule added: {}", rule.description
        );
        self.rules.push(rule);
    }

    /// Load default security rules.
    pub fn load_default_rules(&mut self) {
        // Port scan detection: SYN to port 0
        self.add_rule(IpsRule {
            id: "GE-NET-001".into(),
            description: "SYN scan on port 0 (reconnaissance)".into(),
            severity: "high".into(),
            action: Verdict::Drop,
            criteria: RuleCriteria {
                dst_port: Some(0),
                tcp_flags_mask: Some(0x02),
                tcp_flags_value: Some(0x02),
                ..Default::default()
            },
            enabled: true,
        });

        // XMAS scan detection: FIN+PSH+URG
        self.add_rule(IpsRule {
            id: "GE-NET-002".into(),
            description: "XMAS tree scan detected".into(),
            severity: "high".into(),
            action: Verdict::Drop,
            criteria: RuleCriteria {
                tcp_flags_mask: Some(0x29), // FIN|PSH|URG
                tcp_flags_value: Some(0x29),
                ..Default::default()
            },
            enabled: true,
        });

        // NULL scan detection: no TCP flags
        self.add_rule(IpsRule {
            id: "GE-NET-003".into(),
            description: "NULL scan detected (no TCP flags)".into(),
            severity: "medium".into(),
            action: Verdict::Alert,
            criteria: RuleCriteria {
                protocol: Some(6), // TCP
                tcp_flags_mask: Some(0xFF),
                tcp_flags_value: Some(0x00),
                ..Default::default()
            },
            enabled: true,
        });

        // Modbus write protection
        self.add_rule(IpsRule {
            id: "GE-OT-001".into(),
            description: "Unauthorized Modbus write operation".into(),
            severity: "critical".into(),
            action: Verdict::Drop,
            criteria: RuleCriteria {
                dst_port: Some(502),
                modbus_func_codes: vec![0x05, 0x06, 0x0F, 0x10],
                ..Default::default()
            },
            enabled: true,
        });

        // DNP3 control command protection
        self.add_rule(IpsRule {
            id: "GE-OT-002".into(),
            description: "Unauthorized DNP3 control command".into(),
            severity: "critical".into(),
            action: Verdict::Drop,
            criteria: RuleCriteria {
                dst_port: Some(20000),
                dnp3_func_codes: vec![0x03, 0x04, 0x05, 0x06, 0x0D, 0x0E],
                ..Default::default()
            },
            enabled: true,
        });

        info!(
            rules_count = self.rules.len(),
            "default IPS rules loaded"
        );
    }

    /// Evaluate a packet against all rules and return the verdict.
    pub fn evaluate(
        &mut self,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        tcp_flags: u8,
        modbus_func: Option<u8>,
        dnp3_func: Option<u8>,
    ) -> (Verdict, Option<&IpsRule>) {
        self.stats.packets_inspected += 1;

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.matches_rule(
                rule, src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags,
                modbus_func, dnp3_func,
            ) {
                self.stats.rules_matched += 1;

                let verdict = if self.mode == IpsMode::Tap {
                    // In tap mode, downgrade Drop to Alert
                    if rule.action == Verdict::Drop {
                        Verdict::Alert
                    } else {
                        rule.action
                    }
                } else {
                    rule.action
                };

                match verdict {
                    Verdict::Pass => self.stats.packets_passed += 1,
                    Verdict::Drop => self.stats.packets_dropped += 1,
                    Verdict::Alert => self.stats.packets_alerted += 1,
                }

                return (verdict, Some(rule));
            }
        }

        self.stats.packets_passed += 1;
        (self.default_action, None)
    }

    /// Check if a packet matches a rule's criteria.
    fn matches_rule(
        &self,
        rule: &IpsRule,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        tcp_flags: u8,
        modbus_func: Option<u8>,
        dnp3_func: Option<u8>,
    ) -> bool {
        let c = &rule.criteria;

        if let Some(expected) = c.src_ip {
            if src_ip != Some(expected) {
                return false;
            }
        }
        if let Some(expected) = c.dst_ip {
            if dst_ip != Some(expected) {
                return false;
            }
        }
        if let Some(expected) = c.src_port {
            if src_port != expected {
                return false;
            }
        }
        if let Some(expected) = c.dst_port {
            if dst_port != expected {
                return false;
            }
        }
        if let Some(expected) = c.protocol {
            if protocol != expected {
                return false;
            }
        }
        if let (Some(mask), Some(value)) = (c.tcp_flags_mask, c.tcp_flags_value) {
            if (tcp_flags & mask) != value {
                return false;
            }
        }
        if !c.modbus_func_codes.is_empty() {
            match modbus_func {
                Some(fc) if c.modbus_func_codes.contains(&fc) => {}
                _ => return false,
            }
        }
        if !c.dnp3_func_codes.is_empty() {
            match dnp3_func {
                Some(fc) if c.dnp3_func_codes.contains(&fc) => {}
                _ => return false,
            }
        }

        true
    }

    /// Get engine statistics.
    pub fn stats(&self) -> &IpsStats {
        &self.stats
    }

    /// Get the current mode.
    pub fn mode(&self) -> IpsMode {
        self.mode
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_xmas_scan_blocked_inline() {
        let mut engine = IpsEngine::new(IpsMode::Inline, Verdict::Pass);
        engine.load_default_rules();

        let (verdict, matched_rule) = engine.evaluate(
            Some(ip(10, 0, 0, 1)),
            Some(ip(192, 168, 1, 1)),
            54321,
            80,
            6,    // TCP
            0x29, // FIN|PSH|URG (XMAS)
            None,
            None,
        );

        assert_eq!(verdict, Verdict::Drop);
        assert_eq!(matched_rule.unwrap().id, "GE-NET-002");
    }

    #[test]
    fn test_xmas_scan_alerted_tap() {
        let mut engine = IpsEngine::new(IpsMode::Tap, Verdict::Pass);
        engine.load_default_rules();

        let (verdict, _) = engine.evaluate(
            Some(ip(10, 0, 0, 1)),
            Some(ip(192, 168, 1, 1)),
            54321, 80, 6, 0x29, None, None,
        );

        // In tap mode, Drop is downgraded to Alert
        assert_eq!(verdict, Verdict::Alert);
    }

    #[test]
    fn test_normal_traffic_passes() {
        let mut engine = IpsEngine::new(IpsMode::Inline, Verdict::Pass);
        engine.load_default_rules();

        let (verdict, matched_rule) = engine.evaluate(
            Some(ip(192, 168, 1, 10)),
            Some(ip(10, 0, 0, 1)),
            49152, 443, 6, 0x12, // SYN-ACK (normal)
            None, None,
        );

        assert_eq!(verdict, Verdict::Pass);
        assert!(matched_rule.is_none());
    }

    #[test]
    fn test_modbus_write_blocked() {
        let mut engine = IpsEngine::new(IpsMode::Inline, Verdict::Pass);
        engine.load_default_rules();

        let (verdict, matched_rule) = engine.evaluate(
            Some(ip(10, 0, 0, 50)),
            Some(ip(10, 0, 0, 100)),
            49152,
            502,  // Modbus port
            6,
            0x18, // PSH+ACK
            Some(0x10), // Write Multiple Registers
            None,
        );

        assert_eq!(verdict, Verdict::Drop);
        assert_eq!(matched_rule.unwrap().id, "GE-OT-001");
    }

    #[test]
    fn test_dnp3_control_blocked() {
        let mut engine = IpsEngine::new(IpsMode::Inline, Verdict::Pass);
        engine.load_default_rules();

        let (verdict, matched_rule) = engine.evaluate(
            Some(ip(10, 0, 0, 50)),
            Some(ip(10, 0, 0, 100)),
            49152,
            20000, // DNP3 port
            6,
            0x18,
            None,
            Some(0x03), // DIRECT_OPERATE
        );

        assert_eq!(verdict, Verdict::Drop);
        assert_eq!(matched_rule.unwrap().id, "GE-OT-002");
    }

    #[test]
    fn test_stats_tracking() {
        let mut engine = IpsEngine::new(IpsMode::Inline, Verdict::Pass);
        engine.load_default_rules();

        // Normal packet
        engine.evaluate(Some(ip(10,0,0,1)), Some(ip(10,0,0,2)), 1000, 80, 6, 0x12, None, None);
        // XMAS scan
        engine.evaluate(Some(ip(10,0,0,1)), Some(ip(10,0,0,2)), 1000, 80, 6, 0x29, None, None);

        assert_eq!(engine.stats().packets_inspected, 2);
        assert_eq!(engine.stats().packets_passed, 1);
        assert_eq!(engine.stats().packets_dropped, 1);
    }
}
