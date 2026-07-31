//! tcpdump-like packet formatting.

use std::fmt::Write as FmtWrite;
use std::io::Write;

use anyhow::Result;

use crate::capture::RawPacket;
use crate::cli::Args;
use crate::packet::{AppInfo, DecodedPacket, TransportInfo};

/// Print one decoded packet line (and verbose details) to `out`.
pub fn print_packet(
    out: &mut impl Write,
    raw: &RawPacket,
    decoded: &DecodedPacket,
    args: &Args,
) -> Result<()> {
    let ts = format!("{}.{:06}", raw.timestamp_secs, raw.timestamp_usecs);
    let summary = format_summary(decoded, args);
    let line = if args.link {
        format_link_prefix(decoded, raw.data.len(), &summary)
    } else {
        summary
    };
    writeln!(out, "{ts} {line}")?;

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

    match &decoded.transport {
        Some(TransportInfo::Tcp(tcp)) => {
            let mut s = format!(
                "IP {src}.{sp} > {dst}.{dp}: Flags [{flags}], seq {seq}, ack {ack}, win {win}, length {len}",
                sp = tcp.src_port,
                dp = tcp.dst_port,
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
            let mut s = format!(
                "IP {src}.{sp} > {dst}.{dp}: UDP, length {len} (hdr_len={hdr})",
                sp = udp.src_port,
                dp = udp.dst_port,
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
    // -n is reserved for future name resolution; we always print numeric today.
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
}
