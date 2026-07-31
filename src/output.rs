//! tcpdump-like packet formatting.

use std::fmt::Write as FmtWrite;
use std::io::Write;

use anyhow::Result;

use crate::capture::RawPacket;
use crate::cli::Args;
use crate::packet::{AppInfo, DecodedPacket, TransportInfo};
use crate::services::format_port;

/// How packet timestamps are rendered (tcpdump `-t` count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsMode {
    /// `secs.usecs` since Unix epoch (default / `-tt`).
    Unix,
    /// Omit the timestamp (`-t`).
    None,
    /// Delta from the previous printed packet (`-ttt`).
    Delta,
    /// `YYYY-MM-DD HH:MM:SS.ffffff` UTC (`-tttt`).
    Absolute,
}

impl TsMode {
    /// Map clap `-t` count to a mode (0 and 2 → unix).
    pub fn from_count(count: u8) -> Self {
        match count {
            0 | 2 => Self::Unix,
            1 => Self::None,
            3 => Self::Delta,
            _ => Self::Absolute, // 4+
        }
    }
}

/// Tracks the previous packet time for delta mode.
#[derive(Debug, Default, Clone)]
pub struct TsState {
    prev_micros: Option<u64>,
}

impl TsState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Format a packet timestamp according to mode, updating delta state.
pub fn format_timestamp(raw: &RawPacket, mode: TsMode, state: &mut TsState) -> String {
    let micros = packet_micros(raw);
    let out = match mode {
        TsMode::None => String::new(),
        TsMode::Unix => format!("{}.{:06}", raw.timestamp_secs, raw.timestamp_usecs),
        TsMode::Absolute => format_absolute_utc(u64::from(raw.timestamp_secs), raw.timestamp_usecs),
        TsMode::Delta => {
            let delta = match state.prev_micros {
                Some(prev) => micros.saturating_sub(prev),
                None => 0,
            };
            let secs = delta / 1_000_000;
            let us = delta % 1_000_000;
            format!("{secs}.{us:06}")
        }
    };
    if mode == TsMode::Delta {
        state.prev_micros = Some(micros);
    }
    out
}

fn packet_micros(raw: &RawPacket) -> u64 {
    u64::from(raw.timestamp_secs)
        .saturating_mul(1_000_000)
        .saturating_add(u64::from(raw.timestamp_usecs))
}

/// `YYYY-MM-DD HH:MM:SS.ffffff` in UTC (no chrono dependency).
pub fn format_absolute_utc(secs: u64, usecs: u32) -> String {
    let (y, m, d, hh, mm, ss) = civil_utc(secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}.{usecs:06}")
}

/// Civil date/time from Unix seconds (UTC). Algorithm: Howard Hinnant.
fn civil_utc(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let tod = (secs % 86_400) as u32;
    let hh = tod / 3_600;
    let mm = (tod % 3_600) / 60;
    let ss = tod % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32, hh, mm, ss)
}

/// Print one decoded packet line (and verbose details) to `out`.
pub fn print_packet(
    out: &mut impl Write,
    raw: &RawPacket,
    decoded: &DecodedPacket,
    args: &Args,
    ts_state: &mut TsState,
) -> Result<()> {
    let mode = TsMode::from_count(args.timestamp);
    let ts = format_timestamp(raw, mode, ts_state);
    let summary = format_summary(decoded, args);
    let body = if args.link {
        format_link_prefix(decoded, raw.data.len(), &summary)
    } else {
        summary
    };
    if ts.is_empty() {
        writeln!(out, "{body}")?;
    } else {
        writeln!(out, "{ts} {body}")?;
    }

    if args.verbose > 0 {
        // Skip repeating Ether when -e already printed link headers on the summary line.
        if !args.link {
            if let Some(eth) = &decoded.eth {
                writeln!(
                    out,
                    "    Ether {} > {} ethertype 0x{:04x}",
                    eth.src, eth.dst, eth.ethertype
                )?;
            }
        }
        if let Some(vlan) = decoded.vlan {
            writeln!(out, "    VLAN id {vlan}")?;
        }
        if let Some(ip) = &decoded.ip {
            writeln!(
                out,
                "    IP{} {} > {} proto {} ttl {:?} len {:?}",
                ip.version, ip.src, ip.dst, ip.protocol, ip.ttl, ip.total_len
            )?;
        }
        if args.verbose > 1 {
            match &decoded.app {
                Some(AppInfo::Http(http)) => {
                    writeln!(out, "    HTTP {}", http.summary)?;
                    if let Some(host) = &http.host {
                        writeln!(out, "    Host: {host}")?;
                    }
                }
                Some(AppInfo::Dns(dns)) => {
                    for q in &dns.questions {
                        writeln!(out, "    DNS Q: {q}")?;
                    }
                    for a in &dns.answers {
                        writeln!(out, "    DNS A: {a}")?;
                    }
                }
                Some(AppInfo::Ssh(ssh)) => {
                    writeln!(out, "    SSH {} {}", ssh.proto, ssh.banner)?;
                }
                Some(AppInfo::Tls(tls)) => {
                    writeln!(out, "    TLS {} version={}", tls.handshake, tls.version)?;
                    if let Some(sni) = &tls.sni {
                        writeln!(out, "    SNI: {sni}")?;
                    }
                    if let Some(ja3) = &tls.ja3_hash {
                        writeln!(out, "    JA3: {ja3}")?;
                    }
                    if let Some(ja3s) = &tls.ja3s_hash {
                        writeln!(out, "    JA3S: {ja3s}")?;
                    }
                    if let Some(cs) = &tls.cipher_suite {
                        writeln!(out, "    cipher: {cs}")?;
                    }
                }
                Some(AppInfo::Arp(arp)) => {
                    writeln!(
                        out,
                        "    ARP {} {} ({}) -> {} ({})",
                        arp.operation, arp.sender_mac, arp.sender_ip, arp.target_mac, arp.target_ip
                    )?;
                }
                Some(AppInfo::Dhcp(dhcp)) => {
                    writeln!(
                        out,
                        "    DHCP {} xid={:#x} chaddr={}",
                        dhcp.message_type, dhcp.xid, dhcp.client_mac
                    )?;
                    if let Some(h) = &dhcp.client_hostname {
                        writeln!(out, "    hostname: {h}")?;
                    }
                }
                None => {}
            }
        }
    }

    if args.hex {
        write_hex_dump(out, &raw.data)?;
    } else if args.ascii {
        write_ascii_dump(out, &raw.data)?;
    }

    Ok(())
}

fn format_link_prefix(decoded: &DecodedPacket, frame_len: usize, summary: &str) -> String {
    let Some(eth) = &decoded.eth else {
        return format!("length {frame_len}: {summary}");
    };
    let etype = ethertype_name(eth.ethertype);
    match decoded.vlan {
        Some(vlan) => format!(
            "{} > {}, vlan {vlan}, ethertype {etype} (0x{:04x}), length {frame_len}: {summary}",
            eth.src, eth.dst, eth.ethertype
        ),
        None => format!(
            "{} > {}, ethertype {etype} (0x{:04x}), length {frame_len}: {summary}",
            eth.src, eth.dst, eth.ethertype
        ),
    }
}

fn ethertype_name(etype: u16) -> &'static str {
    match etype {
        0x0800 => "IPv4",
        0x86dd => "IPv6",
        0x0806 => "ARP",
        0x8100 => "802.1Q",
        0x88cc => "LLDP",
        _ => "Unknown",
    }
}

/// Hex + ASCII dump (tcpdump `-X` style), 16 bytes per line.
pub fn write_hex_dump(out: &mut impl Write, data: &[u8]) -> Result<()> {
    for (i, chunk) in data.chunks(16).enumerate() {
        let off = i * 16;
        let mut hex = String::new();
        for (j, b) in chunk.iter().enumerate() {
            if j > 0 {
                hex.push(' ');
            }
            let _ = write!(hex, "{b:02x}");
        }
        // Pad hex columns to a fixed width so ASCII lines up.
        while hex.len() < 47 {
            hex.push(' ');
        }
        let mut ascii = String::new();
        for b in chunk {
            ascii.push(if (0x20..=0x7e).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        writeln!(out, "\t0x{off:04x}:  {hex}  {ascii}")?;
    }
    Ok(())
}

/// ASCII-only dump (tcpdump `-A` style): printable bytes, `.` for others, wrapped.
pub fn write_ascii_dump(out: &mut impl Write, data: &[u8]) -> Result<()> {
    let mut line = String::new();
    for b in data {
        line.push(if (0x20..=0x7e).contains(b) {
            *b as char
        } else if *b == b'\n' || *b == b'\r' || *b == b'\t' {
            // Keep whitespace that aids reading cleartext protocols.
            *b as char
        } else {
            '.'
        });
        if line.len() >= 72 {
            writeln!(out, "\t{line}")?;
            line.clear();
        }
    }
    if !line.is_empty() {
        writeln!(out, "\t{line}")?;
    }
    Ok(())
}

fn format_summary(decoded: &DecodedPacket, args: &Args) -> String {
    let (src, dst) = endpoints(decoded, args.numeric);
    let numeric = args.numeric;

    match &decoded.transport {
        Some(TransportInfo::Tcp(tcp)) => {
            let sp = format_port(tcp.src_port, numeric);
            let dp = format_port(tcp.dst_port, numeric);
            let mut s = format!(
                "IP {src}.{sp} > {dst}.{dp}: Flags [{flags}], seq {seq}, ack {ack}, win {win}, length {len}",
                flags = tcp.flags.label(),
                seq = tcp.seq,
                ack = tcp.ack,
                win = tcp.window,
                len = tcp.payload_len,
            );
            if let Some(AppInfo::Http(http)) = &decoded.app {
                let _ = write!(s, ", HTTP {}", http.method_or_status);
                if let Some(host) = &http.host {
                    let _ = write!(s, " host={host}");
                }
            }
            if let Some(AppInfo::Ssh(ssh)) = &decoded.app {
                let _ = write!(s, ", SSH {}", ssh.banner);
            }
            if let Some(AppInfo::Tls(tls)) = &decoded.app {
                let _ = write!(s, ", TLS {} {}", tls.handshake, tls.version);
                if let Some(sni) = &tls.sni {
                    let _ = write!(s, " sni={sni}");
                }
                if let Some(ja3) = &tls.ja3_hash {
                    let _ = write!(s, " ja3={ja3}");
                }
                if let Some(ja3s) = &tls.ja3s_hash {
                    let _ = write!(s, " ja3s={ja3s}");
                }
                if let Some(cs) = &tls.cipher_suite {
                    let _ = write!(s, " cipher={cs}");
                }
            }
            s
        }
        Some(TransportInfo::Udp(udp)) => {
            let sp = format_port(udp.src_port, numeric);
            let dp = format_port(udp.dst_port, numeric);
            let mut s = format!(
                "IP {src}.{sp} > {dst}.{dp}: UDP, length {len} (hdr_len={hdr})",
                len = udp.payload_len,
                hdr = udp.length,
            );
            if let Some(AppInfo::Dns(dns)) = &decoded.app {
                let kind = if dns.is_query { "query" } else { "response" };
                let q = dns.questions.first().map_or("?", String::as_str);
                let _ = write!(s, ", DNS {kind} id={} {q}", dns.id);
                if let Some(rc) = dns.rcode {
                    let _ = write!(s, " rcode={rc}");
                }
                if !dns.is_query {
                    if let Some(a) = dns.answers.first() {
                        let _ = write!(s, " => {a}");
                    }
                }
            }
            if let Some(AppInfo::Dhcp(dhcp)) = &decoded.app {
                let _ = write!(
                    s,
                    ", DHCP {} xid={:#x} mac={}",
                    dhcp.message_type, dhcp.xid, dhcp.client_mac
                );
                if let Some(h) = &dhcp.client_hostname {
                    let _ = write!(s, " host={h}");
                }
                if let Some(yi) = &dhcp.your_ip {
                    let _ = write!(s, " yiaddr={yi}");
                }
            }
            s
        }
        Some(TransportInfo::Icmp(icmp)) => {
            format!(
                "IP {src} > {dst}: {} (v{} type={} code={})",
                icmp.summary, icmp.version, icmp.type_u8, icmp.code
            )
        }
        Some(TransportInfo::Other { protocol }) => {
            format!(
                "IP {src} > {dst}: proto {protocol} length {}",
                decoded.payload_len
            )
        }
        None => {
            if let Some(AppInfo::Arp(arp)) = &decoded.app {
                format!(
                    "ARP {op} {sm} ({sip}) > {tm} ({tip})",
                    op = arp.operation,
                    sm = arp.sender_mac,
                    sip = arp.sender_ip,
                    tm = arp.target_mac,
                    tip = arp.target_ip,
                )
            } else if let Some(eth) = &decoded.eth {
                format!(
                    "Ether {} > {} ethertype 0x{:04x} length {}",
                    eth.src, eth.dst, eth.ethertype, decoded.payload_len
                )
            } else {
                format!("frame length {}", decoded.payload_len)
            }
        }
    }
}

fn endpoints(decoded: &DecodedPacket, _numeric: bool) -> (String, String) {
    // Addresses stay numeric (no DNS). Port service names use `format_port` when !numeric.
    if let Some(ip) = &decoded.ip {
        (ip.src.to_string(), ip.dst.to_string())
    } else if let Some(eth) = &decoded.eth {
        (eth.src.clone(), eth.dst.clone())
    } else {
        ("?".into(), "?".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_aligns_ascii() {
        let data: Vec<u8> = (0u8..20).collect();
        let mut buf = Vec::new();
        write_hex_dump(&mut buf, &data).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("0x0000:"));
        assert!(s.contains("0x0010:"));
        assert!(s.contains("  ................"));
    }

    #[test]
    fn ascii_dump_prints_printable() {
        let mut buf = Vec::new();
        write_ascii_dump(&mut buf, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("GET / HTTP/1.1"));
        assert!(s.contains("Host: x"));
    }

    #[test]
    fn ascii_dump_dots_binary() {
        let mut buf = Vec::new();
        write_ascii_dump(&mut buf, &[0x00, 0x01, b'A', 0xff]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("..A."));
    }

    #[test]
    fn link_prefix_includes_macs_and_ethertype() {
        use crate::packet::EthernetInfo;
        let decoded = DecodedPacket {
            eth: Some(EthernetInfo {
                src: "aa:bb:cc:dd:ee:ff".into(),
                dst: "11:22:33:44:55:66".into(),
                ethertype: 0x0800,
            }),
            ..Default::default()
        };
        let line = format_link_prefix(&decoded, 98, "IP 1.1.1.1 > 2.2.2.2: UDP");
        assert!(line.contains("aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66"));
        assert!(line.contains("ethertype IPv4 (0x0800)"));
        assert!(line.contains("length 98:"));
        assert!(line.contains("UDP"));
    }

    #[test]
    fn absolute_utc_known_epoch() {
        // 2023-11-14 22:13:20 UTC
        let s = format_absolute_utc(1_700_000_000, 123_456);
        assert_eq!(s, "2023-11-14 22:13:20.123456");
    }

    #[test]
    fn delta_mode_tracks_previous() {
        let mut state = TsState::new();
        let a = RawPacket {
            timestamp_secs: 100,
            timestamp_usecs: 0,
            orig_len: 0,
            data: vec![],
        };
        let b = RawPacket {
            timestamp_secs: 100,
            timestamp_usecs: 500,
            orig_len: 0,
            data: vec![],
        };
        assert_eq!(format_timestamp(&a, TsMode::Delta, &mut state), "0.000000");
        assert_eq!(format_timestamp(&b, TsMode::Delta, &mut state), "0.000500");
        assert!(format_timestamp(&a, TsMode::None, &mut state).is_empty());
    }
}
