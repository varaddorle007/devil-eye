//! Bounded traffic statistics.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;

use anyhow::Result;
use serde::Serialize;

use crate::packet::{DecodedPacket, TransportInfo};

const TOP_N: usize = 10;
const MAX_TRACKED: usize = 256;

/// Serializable protocol / volume counters for dashboards and reports.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other: u64,
    pub dns: u64,
    pub http: u64,
    pub ssh: u64,
    pub tls: u64,
    pub arp: u64,
    pub dhcp: u64,
    pub top_sources: Vec<CountEntry>,
    pub top_destinations: Vec<CountEntry>,
    pub top_dst_ports: Vec<PortCount>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CountEntry {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PortCount {
    pub port: u16,
    pub count: u64,
}

#[derive(Debug, Default)]
pub struct TrafficStats {
    packets: u64,
    bytes: u64,
    tcp: u64,
    udp: u64,
    icmp: u64,
    other: u64,
    dns: u64,
    http: u64,
    ssh: u64,
    tls: u64,
    arp: u64,
    dhcp: u64,
    dropped: u64,
    if_dropped: u64,
    received: u64,
    by_src: HashMap<IpAddr, u64>,
    by_dst: HashMap<IpAddr, u64>,
    by_sport: HashMap<u16, u64>,
    by_dport: HashMap<u16, u64>,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_capture_stats(&mut self, received: u64, dropped: u64, if_dropped: u64) {
        self.received = received;
        self.dropped = dropped;
        self.if_dropped = if_dropped;
    }

    pub fn record_raw(&mut self, len: usize) {
        self.packets += 1;
        self.bytes += len as u64;
        self.other += 1;
    }

    pub fn record(&mut self, decoded: &DecodedPacket, frame_len: usize) {
        self.packets += 1;
        self.bytes += frame_len as u64;

        if let Some(ip) = &decoded.ip {
            bump_capped(&mut self.by_src, ip.src);
            bump_capped(&mut self.by_dst, ip.dst);
        }

        match &decoded.transport {
            Some(TransportInfo::Tcp(tcp)) => {
                self.tcp += 1;
                bump_capped(&mut self.by_sport, tcp.src_port);
                bump_capped(&mut self.by_dport, tcp.dst_port);
            }
            Some(TransportInfo::Udp(udp)) => {
                self.udp += 1;
                bump_capped(&mut self.by_sport, udp.src_port);
                bump_capped(&mut self.by_dport, udp.dst_port);
            }
            Some(TransportInfo::Icmp(_)) => self.icmp += 1,
            Some(TransportInfo::Other { .. }) | None => self.other += 1,
        }

        match &decoded.app {
            Some(crate::packet::AppInfo::Dns(_)) => self.dns += 1,
            Some(crate::packet::AppInfo::Http(_)) => self.http += 1,
            Some(crate::packet::AppInfo::Ssh(_)) => self.ssh += 1,
            Some(crate::packet::AppInfo::Tls(_)) => self.tls += 1,
            Some(crate::packet::AppInfo::Arp(_)) => self.arp += 1,
            Some(crate::packet::AppInfo::Dhcp(_)) => self.dhcp += 1,
            None => {}
        }
    }

    /// Packets observed so far.
    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Bytes observed so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Snapshot counters for live dashboards / JSON APIs.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets: self.packets,
            bytes: self.bytes,
            tcp: self.tcp,
            udp: self.udp,
            icmp: self.icmp,
            other: self.other,
            dns: self.dns,
            http: self.http,
            ssh: self.ssh,
            tls: self.tls,
            arp: self.arp,
            dhcp: self.dhcp,
            top_sources: top_addrs(&self.by_src, TOP_N),
            top_destinations: top_addrs(&self.by_dst, TOP_N),
            top_dst_ports: top_ports(&self.by_dport, TOP_N),
        }
    }

    pub fn print_periodic(&self, err: &mut impl Write) -> Result<()> {
        writeln!(
            err,
            "stats: packets={} bytes={} tcp={} udp={} icmp={} other={} dns={} http={} ssh={} tls={} arp={} dhcp={}",
            self.packets,
            self.bytes,
            self.tcp,
            self.udp,
            self.icmp,
            self.other,
            self.dns,
            self.http,
            self.ssh,
            self.tls,
            self.arp,
            self.dhcp
        )?;
        Ok(())
    }

    pub fn print_final(&self, err: &mut impl Write, decode_failures: u64) -> Result<()> {
        writeln!(err, "--- devil-eye statistics ---")?;
        writeln!(err, "  packets:         {}", self.packets)?;
        writeln!(err, "  bytes:           {}", self.bytes)?;
        writeln!(err, "  tcp:             {}", self.tcp)?;
        writeln!(err, "  udp:             {}", self.udp)?;
        writeln!(err, "  icmp:            {}", self.icmp)?;
        writeln!(err, "  other:           {}", self.other)?;
        writeln!(err, "  dns:             {}", self.dns)?;
        writeln!(err, "  http:            {}", self.http)?;
        writeln!(err, "  ssh:             {}", self.ssh)?;
        writeln!(err, "  tls:             {}", self.tls)?;
        writeln!(err, "  arp:             {}", self.arp)?;
        writeln!(err, "  dhcp:            {}", self.dhcp)?;
        writeln!(err, "  decode failures: {decode_failures}")?;
        writeln!(err, "  capture received: {}", self.received)?;
        writeln!(
            err,
            "  capture drops:   {} (if_dropped {})",
            self.dropped, self.if_dropped
        )?;
        write_top(err, "top sources", &self.by_src)?;
        write_top(err, "top destinations", &self.by_dst)?;
        write_top_ports(err, "top src ports", &self.by_sport)?;
        write_top_ports(err, "top dst ports", &self.by_dport)?;
        Ok(())
    }
}

fn bump_capped<K: Eq + std::hash::Hash + Copy>(map: &mut HashMap<K, u64>, key: K) {
    if map.len() >= MAX_TRACKED && !map.contains_key(&key) {
        return;
    }
    *map.entry(key).or_insert(0) += 1;
}

fn top_addrs(map: &HashMap<IpAddr, u64>, n: usize) -> Vec<CountEntry> {
    let mut items: Vec<_> = map.iter().collect();
    items.sort_by(|a, b| {
        b.1.cmp(a.1)
            .then_with(|| format!("{}", a.0).cmp(&format!("{}", b.0)))
    });
    items
        .into_iter()
        .take(n)
        .map(|(addr, count)| CountEntry {
            key: addr.to_string(),
            count: *count,
        })
        .collect()
}

fn top_ports(map: &HashMap<u16, u64>, n: usize) -> Vec<PortCount> {
    let mut items: Vec<_> = map.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    items
        .into_iter()
        .take(n)
        .map(|(port, count)| PortCount {
            port: *port,
            count: *count,
        })
        .collect()
}

fn write_top(err: &mut impl Write, title: &str, map: &HashMap<IpAddr, u64>) -> Result<()> {
    if map.is_empty() {
        return Ok(());
    }
    writeln!(err, "  {title}:")?;
    let mut items: Vec<_> = map.iter().collect();
    items.sort_by(|a, b| {
        b.1.cmp(a.1)
            .then_with(|| format!("{}", a.0).cmp(&format!("{}", b.0)))
    });
    for (addr, count) in items.into_iter().take(TOP_N) {
        writeln!(err, "    {addr}: {count}")?;
    }
    Ok(())
}

fn write_top_ports(err: &mut impl Write, title: &str, map: &HashMap<u16, u64>) -> Result<()> {
    if map.is_empty() {
        return Ok(());
    }
    writeln!(err, "  {title}:")?;
    let mut items: Vec<_> = map.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    for (port, count) in items.into_iter().take(TOP_N) {
        writeln!(err, "    {port}: {count}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IpInfo, TcpFlags, TcpInfo};
    use std::net::Ipv4Addr;

    #[test]
    fn counts_tcp() {
        let mut s = TrafficStats::new();
        let decoded = DecodedPacket {
            ip: Some(IpInfo {
                src: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                dst: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(40),
            }),
            transport: Some(TransportInfo::Tcp(TcpInfo {
                src_port: 1234,
                dst_port: 80,
                seq: 1,
                ack: 0,
                flags: TcpFlags {
                    syn: true,
                    ..Default::default()
                },
                window: 64240,
                payload_len: 0,
            })),
            ..Default::default()
        };
        s.record(&decoded, 54);
        assert_eq!(s.packets, 1);
        assert_eq!(s.tcp, 1);
        assert_eq!(s.by_dport.get(&80), Some(&1));
    }
}
