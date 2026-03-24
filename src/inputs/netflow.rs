//! NetFlow v5/v9 receiver — async UDP listener.
//!
//! Receives NetFlow records and converts them into synthetic flow events
//! for the output pipeline.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// A parsed NetFlow record.
#[derive(Debug, Clone)]
pub struct NetFlowRecord {
    /// NetFlow version (5 or 9)
    pub version: u16,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// IP protocol number
    pub protocol: u8,
    /// Total bytes in flow
    pub bytes: u64,
    /// Total packets in flow
    pub packets: u64,
    /// Flow start time (sysUpTime ms)
    pub first_switched: u32,
    /// Flow end time (sysUpTime ms)
    pub last_switched: u32,
    /// TCP flags OR'd
    pub tcp_flags: u8,
    /// Receive timestamp
    pub timestamp: String,
}

/// Parse NetFlow v5 packet.
/// NetFlow v5 header is 24 bytes, each record is 48 bytes.
pub fn parse_netflow_v5(data: &[u8]) -> Vec<NetFlowRecord> {
    let mut records = Vec::new();

    if data.len() < 24 {
        return records;
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 5 {
        return records;
    }

    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    let now = chrono::Utc::now().to_rfc3339();

    for i in 0..count {
        let offset = 24 + i * 48;
        if offset + 48 > data.len() {
            break;
        }

        let src_ip = Ipv4Addr::new(
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        );
        let dst_ip = Ipv4Addr::new(
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        );

        let packets = u32::from_be_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]) as u64;
        let bytes = u32::from_be_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]) as u64;

        let first_switched = u32::from_be_bytes([
            data[offset + 24],
            data[offset + 25],
            data[offset + 26],
            data[offset + 27],
        ]);
        let last_switched = u32::from_be_bytes([
            data[offset + 28],
            data[offset + 29],
            data[offset + 30],
            data[offset + 31],
        ]);

        let src_port = u16::from_be_bytes([data[offset + 32], data[offset + 33]]);
        let dst_port = u16::from_be_bytes([data[offset + 34], data[offset + 35]]);
        let tcp_flags = data[offset + 37];
        let protocol = data[offset + 38];

        records.push(NetFlowRecord {
            version: 5,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port,
            dst_port,
            protocol,
            bytes,
            packets,
            first_switched,
            last_switched,
            tcp_flags,
            timestamp: now.clone(),
        });
    }

    records
}

/// Start the NetFlow UDP receiver.
pub async fn start_netflow_udp(
    addr: SocketAddr,
    sender: mpsc::Sender<NetFlowRecord>,
) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("failed to bind NetFlow UDP on {addr}"))?;

    info!(addr = %addr, "NetFlow UDP receiver started");

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _peer)) => {
                let records = parse_netflow_v5(&buf[..len]);
                for record in records {
                    if sender.try_send(record).is_err() {
                        debug!("NetFlow channel full — dropping record");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "NetFlow UDP recv error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_netflow_v5_packet(count: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 24 + count as usize * 48];
        // Header
        pkt[0] = 0x00; pkt[1] = 0x05; // version 5
        pkt[2] = (count >> 8) as u8;
        pkt[3] = count as u8;

        // First record
        if count > 0 {
            let offset = 24;
            // src: 192.168.1.1
            pkt[offset] = 192; pkt[offset + 1] = 168; pkt[offset + 2] = 1; pkt[offset + 3] = 1;
            // dst: 10.0.0.1
            pkt[offset + 4] = 10; pkt[offset + 5] = 0; pkt[offset + 6] = 0; pkt[offset + 7] = 1;
            // packets = 100
            pkt[offset + 19] = 100;
            // bytes = 50000
            pkt[offset + 22] = 0xC3; pkt[offset + 23] = 0x50;
            // src_port = 12345
            pkt[offset + 32] = 0x30; pkt[offset + 33] = 0x39;
            // dst_port = 80
            pkt[offset + 35] = 0x50;
            // tcp_flags = SYN|ACK
            pkt[offset + 37] = 0x12;
            // protocol = TCP (6)
            pkt[offset + 38] = 6;
        }

        pkt
    }

    #[test]
    fn test_netflow_v5_parse() {
        let pkt = make_netflow_v5_packet(1);
        let records = parse_netflow_v5(&pkt);
        assert_eq!(records.len(), 1);

        let r = &records[0];
        assert_eq!(r.version, 5);
        assert_eq!(r.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(r.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(r.src_port, 12345);
        assert_eq!(r.dst_port, 80);
        assert_eq!(r.protocol, 6);
        assert_eq!(r.packets, 100);
        assert_eq!(r.tcp_flags, 0x12);
    }

    #[test]
    fn test_netflow_too_short() {
        let records = parse_netflow_v5(&[0u8; 10]);
        assert!(records.is_empty());
    }

    #[test]
    fn test_netflow_wrong_version() {
        let mut pkt = vec![0u8; 72]; // header + 1 record
        pkt[0] = 0x00; pkt[1] = 0x09; // version 9
        let records = parse_netflow_v5(&pkt);
        assert!(records.is_empty());
    }
}
