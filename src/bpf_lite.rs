//! Offline software packet filter (tcpdump-like subset, no libpcap).
//!
//! Supported primitives (case-insensitive):
//! - protocols: `ip`, `ip6`, `arp`, `tcp`, `udp`, `icmp`, `icmp6`
//! - `vlan` (any 802.1Q tag) / `vlan N` (VID 0–4095)
//! - `[src|dst] port N`, `[src|dst] portrange N-M`
//! - `[src|dst] host ADDR`, `[src|dst] net CIDR`
//! - TCP flags: `tcp-syn`, `tcp-ack`, `tcp-fin`, `tcp-rst`, `tcp-psh`, `tcp-urg`, `tcp-synack`
//! - length: `less N`, `greater N` (Ethernet frame byte length)
//! - combinators: `and` / `&&`, `or` / `||`, `not` / `!`, parentheses
//!
//! Chained forms like `udp port 53` and `tcp dst port 80` are supported.

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

use crate::decode::decode_packet;
use crate::packet::{DecodedPacket, TransportInfo};

/// Compiled offline filter expression.
#[derive(Debug, Clone)]
pub struct PacketFilter {
    root: Expr,
}

impl PacketFilter {
    /// Parse a filter expression. Empty / whitespace-only matches everything.
    pub fn parse(expr: &str) -> Result<Self> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Ok(Self { root: Expr::True });
        }
        let tokens = tokenize(trimmed)?;
        let mut parser = Parser {
            tokens: &tokens,
            pos: 0,
        };
        let root = parser.parse_or()?;
        if parser.pos != tokens.len() {
            bail!(
                "unexpected token '{}' in filter (supported: tcpdump-like subset)",
                tokens[parser.pos]
            );
        }
        Ok(Self { root })
    }

    /// Return true when the Ethernet frame matches this filter.
    pub fn matches(&self, frame: &[u8]) -> bool {
        let Ok(decoded) = decode_packet(frame) else {
            return false;
        };
        eval(&self.root, &decoded, frame.len())
    }
}

#[derive(Debug, Clone)]
enum Expr {
    True,
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Proto(ProtoKind),
    Port { dir: Dir, port: u16 },
    PortRange { dir: Dir, lo: u16, hi: u16 },
    Host { dir: Dir, addr: IpAddr },
    Net { dir: Dir, net: IpNet },
    /// Any VLAN tag (`None`) or a specific VID (`Some`).
    Vlan { id: Option<u16> },
    TcpFlags {
        syn: Option<bool>,
        ack: Option<bool>,
        fin: Option<bool>,
        rst: Option<bool>,
        psh: Option<bool>,
        urg: Option<bool>,
    },
    Less(usize),
    Greater(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Any,
    Src,
    Dst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoKind {
    Ip,
    Ip6,
    Arp,
    Tcp,
    Udp,
    Icmp,
    Icmp6,
}

struct Parser<'a> {
    tokens: &'a [String],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(String::as_str)
    }

    fn bump(&mut self) -> Option<&str> {
        let t = self.tokens.get(self.pos).map(String::as_str);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while matches!(
            self.peek().map(str::to_ascii_lowercase).as_deref(),
            Some("or" | "||")
        ) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        while matches!(
            self.peek().map(str::to_ascii_lowercase).as_deref(),
            Some("and" | "&&")
        ) {
            self.bump();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if matches!(
            self.peek().map(str::to_ascii_lowercase).as_deref(),
            Some("not" | "!")
        ) {
            self.bump();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        if self.peek() == Some("(") {
            self.bump();
            let inner = self.parse_or()?;
            match self.bump() {
                Some(")") => Ok(inner),
                other => bail!("expected ')' after filter group, got {other:?}"),
            }
        } else {
            self.parse_primitive()
        }
    }

    fn parse_primitive(&mut self) -> Result<Expr> {
        if matches!(
            self.peek().map(str::to_ascii_lowercase).as_deref(),
            Some("less")
        ) {
            self.bump();
            let n = self
                .bump()
                .ok_or_else(|| anyhow::anyhow!("expected length after less"))?
                .parse::<usize>()
                .context("invalid less length")?;
            return Ok(Expr::Less(n));
        }
        if matches!(
            self.peek().map(str::to_ascii_lowercase).as_deref(),
            Some("greater")
        ) {
            self.bump();
            let n = self
                .bump()
                .ok_or_else(|| anyhow::anyhow!("expected length after greater"))?
                .parse::<usize>()
                .context("invalid greater length")?;
            return Ok(Expr::Greater(n));
        }
        if let Some(flags) = self.peek().and_then(tcp_flag_shortcut) {
            self.bump();
            return Ok(Expr::And(
                Box::new(Expr::Proto(ProtoKind::Tcp)),
                Box::new(flags),
            ));
        }

        // `vlan` / `vlan N` stand alone (not chained with proto like `udp port`).
        if matches!(
            self.peek().map(str::to_ascii_lowercase).as_deref(),
            Some("vlan")
        ) {
            self.bump();
            if let Some(tok) = self.peek() {
                if let Ok(id) = tok.parse::<u16>() {
                    if id > 4095 {
                        bail!("VLAN id {id} out of range (0-4095)");
                    }
                    self.bump();
                    return Ok(Expr::Vlan { id: Some(id) });
                }
            }
            return Ok(Expr::Vlan { id: None });
        }

        let mut protos = Vec::new();
        while let Some(kind) = self.peek().and_then(proto_kind) {
            self.bump();
            protos.push(Expr::Proto(kind));
        }

        let dir = match self.peek().map(str::to_ascii_lowercase).as_deref() {
            Some("src") => {
                self.bump();
                Dir::Src
            }
            Some("dst") => {
                self.bump();
                Dir::Dst
            }
            _ => Dir::Any,
        };

        let keyed = match self.peek().map(str::to_ascii_lowercase).as_deref() {
            Some("port") => {
                self.bump();
                let port = self
                    .bump()
                    .ok_or_else(|| anyhow::anyhow!("expected port number"))?
                    .parse::<u16>()
                    .context("invalid port number")?;
                Some(Expr::Port { dir, port })
            }
            Some("portrange") => {
                self.bump();
                let raw = self
                    .bump()
                    .ok_or_else(|| anyhow::anyhow!("expected portrange N-M"))?;
                let (lo, hi) = parse_portrange(raw)?;
                Some(Expr::PortRange { dir, lo, hi })
            }
            Some("host") => {
                self.bump();
                let raw = self
                    .bump()
                    .ok_or_else(|| anyhow::anyhow!("expected host address"))?;
                let addr = IpAddr::from_str(raw).with_context(|| format!("invalid host '{raw}'"))?;
                Some(Expr::Host { dir, addr })
            }
            Some("net") => {
                self.bump();
                let raw = self
                    .bump()
                    .ok_or_else(|| anyhow::anyhow!("expected net CIDR"))?;
                let net = parse_net(raw)?;
                Some(Expr::Net { dir, net })
            }
            _ => None,
        };

        if protos.is_empty() && keyed.is_none() {
            let tok = self.peek().unwrap_or("<eof>");
            bail!(
                "expected filter primitive near '{tok}' \
                 (examples: 'udp port 53', 'vlan 100', 'tcp-syn', 'host 1.2.3.4')"
            );
        }

        let mut parts = protos;
        if let Some(k) = keyed {
            parts.push(k);
        }
        Ok(fold_and(parts))
    }
}

fn fold_and(parts: Vec<Expr>) -> Expr {
    parts
        .into_iter()
        .reduce(|a, b| Expr::And(Box::new(a), Box::new(b)))
        .unwrap_or(Expr::True)
}

fn tcp_flag_shortcut(tok: &str) -> Option<Expr> {
    let lower = tok.to_ascii_lowercase();
    let flags = match lower.as_str() {
        "tcp-syn" | "tcp[syn]" => Expr::TcpFlags {
            syn: Some(true),
            ack: Some(false),
            fin: None,
            rst: None,
            psh: None,
            urg: None,
        },
        "tcp-ack" => Expr::TcpFlags {
            syn: None,
            ack: Some(true),
            fin: None,
            rst: None,
            psh: None,
            urg: None,
        },
        "tcp-fin" => Expr::TcpFlags {
            syn: None,
            ack: None,
            fin: Some(true),
            rst: None,
            psh: None,
            urg: None,
        },
        "tcp-rst" => Expr::TcpFlags {
            syn: None,
            ack: None,
            fin: None,
            rst: Some(true),
            psh: None,
            urg: None,
        },
        "tcp-psh" => Expr::TcpFlags {
            syn: None,
            ack: None,
            fin: None,
            rst: None,
            psh: Some(true),
            urg: None,
        },
        "tcp-urg" => Expr::TcpFlags {
            syn: None,
            ack: None,
            fin: None,
            rst: None,
            psh: None,
            urg: Some(true),
        },
        "tcp-synack" | "tcp-syn-ack" => Expr::TcpFlags {
            syn: Some(true),
            ack: Some(true),
            fin: None,
            rst: None,
            psh: None,
            urg: None,
        },
        _ => return None,
    };
    Some(flags)
}

fn proto_kind(tok: &str) -> Option<ProtoKind> {
    match tok.to_ascii_lowercase().as_str() {
        "ip" => Some(ProtoKind::Ip),
        "ip6" | "ipv6" => Some(ProtoKind::Ip6),
        "arp" => Some(ProtoKind::Arp),
        "tcp" => Some(ProtoKind::Tcp),
        "udp" => Some(ProtoKind::Udp),
        "icmp" => Some(ProtoKind::Icmp),
        "icmp6" | "icmpv6" => Some(ProtoKind::Icmp6),
        _ => None,
    }
}

fn parse_portrange(raw: &str) -> Result<(u16, u16)> {
    let (a, b) = raw
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("portrange must be N-M, got '{raw}'"))?;
    let lo: u16 = a.parse().context("invalid portrange low")?;
    let hi: u16 = b.parse().context("invalid portrange high")?;
    if lo > hi {
        bail!("portrange low ({lo}) > high ({hi})");
    }
    Ok((lo, hi))
}

fn parse_net(raw: &str) -> Result<IpNet> {
    if let Ok(net) = IpNet::from_str(raw) {
        return Ok(net);
    }
    // Bare address → /32 or /128
    let addr = IpAddr::from_str(raw).with_context(|| format!("invalid net '{raw}'"))?;
    Ok(IpNet::from(addr))
}

fn tokenize(expr: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' || c == ')' {
            tokens.push(c.to_string());
            i += 1;
            continue;
        }
        if c == '!' {
            tokens.push("!".into());
            i += 1;
            continue;
        }
        if c == '&' && i + 1 < chars.len() && chars[i + 1] == '&' {
            tokens.push("&&".into());
            i += 2;
            continue;
        }
        if c == '|' && i + 1 < chars.len() && chars[i + 1] == '|' {
            tokens.push("||".into());
            i += 2;
            continue;
        }
        let start = i;
        while i < chars.len() {
            let ch = chars[i];
            if ch.is_whitespace() || matches!(ch, '(' | ')' | '!' | '&' | '|') {
                break;
            }
            i += 1;
        }
        if start == i {
            bail!("unexpected character '{c}' in filter");
        }
        tokens.push(chars[start..i].iter().collect());
    }
    Ok(tokens)
}

fn eval(expr: &Expr, pkt: &DecodedPacket, frame_len: usize) -> bool {
    match expr {
        Expr::True => true,
        Expr::And(a, b) => eval(a, pkt, frame_len) && eval(b, pkt, frame_len),
        Expr::Or(a, b) => eval(a, pkt, frame_len) || eval(b, pkt, frame_len),
        Expr::Not(a) => !eval(a, pkt, frame_len),
        Expr::Proto(kind) => match_proto(*kind, pkt),
        Expr::Port { dir, port } => match_port(*dir, |p| p == *port, pkt),
        Expr::PortRange { dir, lo, hi } => match_port(*dir, |p| p >= *lo && p <= *hi, pkt),
        Expr::Host { dir, addr } => match_host(*dir, *addr, pkt),
        Expr::Net { dir, net } => match_net(*dir, *net, pkt),
        Expr::Vlan { id: None } => pkt.vlan.is_some(),
        Expr::Vlan { id: Some(want) } => pkt.vlan == Some(*want),
        Expr::TcpFlags {
            syn,
            ack,
            fin,
            rst,
            psh,
            urg,
        } => match &pkt.transport {
            Some(TransportInfo::Tcp(t)) => {
                syn.is_none_or(|v| t.flags.syn == v)
                    && ack.is_none_or(|v| t.flags.ack == v)
                    && fin.is_none_or(|v| t.flags.fin == v)
                    && rst.is_none_or(|v| t.flags.rst == v)
                    && psh.is_none_or(|v| t.flags.psh == v)
                    && urg.is_none_or(|v| t.flags.urg == v)
            }
            _ => false,
        },
        Expr::Less(n) => frame_len < *n,
        Expr::Greater(n) => frame_len > *n,
    }
}

fn match_proto(kind: ProtoKind, pkt: &DecodedPacket) -> bool {
    match kind {
        ProtoKind::Ip => pkt.ip.as_ref().is_some_and(|ip| ip.version == 4),
        ProtoKind::Ip6 => pkt.ip.as_ref().is_some_and(|ip| ip.version == 6),
        ProtoKind::Arp => pkt
            .eth
            .as_ref()
            .is_some_and(|e| e.ethertype == 0x0806)
            || pkt.app.as_ref().is_some_and(|a| {
                matches!(a, crate::packet::AppInfo::Arp(_))
            }),
        ProtoKind::Tcp => matches!(pkt.transport, Some(TransportInfo::Tcp(_))),
        ProtoKind::Udp => matches!(pkt.transport, Some(TransportInfo::Udp(_))),
        ProtoKind::Icmp => matches!(
            pkt.transport,
            Some(TransportInfo::Icmp(ref i)) if i.version == 4
        ) || pkt.ip.as_ref().is_some_and(|ip| ip.protocol == 1),
        ProtoKind::Icmp6 => matches!(
            pkt.transport,
            Some(TransportInfo::Icmp(ref i)) if i.version == 6
        ) || pkt.ip.as_ref().is_some_and(|ip| ip.protocol == 58),
    }
}

fn match_port(dir: Dir, pred: impl Fn(u16) -> bool, pkt: &DecodedPacket) -> bool {
    let (src, dst) = match &pkt.transport {
        Some(TransportInfo::Tcp(t)) => (t.src_port, t.dst_port),
        Some(TransportInfo::Udp(u)) => (u.src_port, u.dst_port),
        _ => return false,
    };
    match dir {
        Dir::Any => pred(src) || pred(dst),
        Dir::Src => pred(src),
        Dir::Dst => pred(dst),
    }
}

fn match_host(dir: Dir, addr: IpAddr, pkt: &DecodedPacket) -> bool {
    let Some(ip) = &pkt.ip else {
        return false;
    };
    match dir {
        Dir::Any => ip.src == addr || ip.dst == addr,
        Dir::Src => ip.src == addr,
        Dir::Dst => ip.dst == addr,
    }
}

fn match_net(dir: Dir, net: IpNet, pkt: &DecodedPacket) -> bool {
    let Some(ip) = &pkt.ip else {
        return false;
    };
    match dir {
        Dir::Any => net.contains(&ip.src) || net.contains(&ip.dst),
        Dir::Src => net.contains(&ip.src),
        Dir::Dst => net.contains(&ip.dst),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn frame(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let mut src = crate::capture::OfflineSource::open(&path).unwrap();
        src.next_packet().unwrap().unwrap().data
    }

    #[test]
    fn parses_udp_port() {
        let f = PacketFilter::parse("udp port 53").unwrap();
        assert!(f.matches(&frame("dns_query.pcap")));
        assert!(!f.matches(&frame("http_get.pcap")));
    }

    #[test]
    fn parses_tcp_and_not_udp() {
        let f = PacketFilter::parse("tcp and not udp").unwrap();
        assert!(f.matches(&frame("http_get.pcap")));
        assert!(!f.matches(&frame("dns_query.pcap")));
    }

    #[test]
    fn parses_arp() {
        let f = PacketFilter::parse("arp").unwrap();
        assert!(f.matches(&frame("arp_request.pcap")));
        assert!(!f.matches(&frame("dns_query.pcap")));
    }

    #[test]
    fn rejects_garbage() {
        let err = PacketFilter::parse("foo bar").unwrap_err();
        assert!(err.to_string().contains("primitive"));
    }

    #[test]
    fn empty_matches_all() {
        let f = PacketFilter::parse("").unwrap();
        assert!(f.matches(&frame("dns_query.pcap")));
    }

    /// Minimal Ethernet + 802.1Q + IPv4/UDP frame (VID in TCI).
    fn vlan_udp_frame(vid: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src
        frame.extend_from_slice(&0x8100u16.to_be_bytes()); // 802.1Q
        frame.extend_from_slice(&(vid & 0x0fff).to_be_bytes()); // TCI
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // IPv4 header (20 bytes) + UDP (8) + payload
        let mut ip = vec![
            0x45, 0x00, 0x00, 0x1c, // ver/ihl, tos, total len 28
            0x00, 0x01, 0x00, 0x00, // id, flags
            0x40, 0x11, 0x00, 0x00, // ttl, proto UDP, checksum
            10, 0, 0, 1, // src
            10, 0, 0, 2, // dst
        ];
        // UDP
        ip.extend_from_slice(&53u16.to_be_bytes());
        ip.extend_from_slice(&53_000u16.to_be_bytes());
        ip.extend_from_slice(&8u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    fn vlan_any_and_id_match() {
        let tagged = vlan_udp_frame(100);
        let untagged = frame("dns_query.pcap");

        let any = PacketFilter::parse("vlan").unwrap();
        assert!(any.matches(&tagged));
        assert!(!any.matches(&untagged));

        let id100 = PacketFilter::parse("vlan 100").unwrap();
        assert!(id100.matches(&tagged));
        assert!(!id100.matches(&vlan_udp_frame(200)));

        let combo = PacketFilter::parse("vlan 100 and udp").unwrap();
        assert!(combo.matches(&tagged));
        assert!(!PacketFilter::parse("vlan 100 and tcp").unwrap().matches(&tagged));
    }

    #[test]
    fn vlan_id_out_of_range() {
        let err = PacketFilter::parse("vlan 4096").unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn parses_tcp_syn_shortcut() {
        let f = PacketFilter::parse("tcp-syn").unwrap();
        // established HTTP GET is not a lone SYN
        assert!(!f.matches(&frame("http_get.pcap")));
    }

    #[test]
    fn parses_less_greater() {
        let dns = frame("dns_query.pcap");
        let f = PacketFilter::parse(&format!("greater {}", dns.len() - 1)).unwrap();
        assert!(f.matches(&dns));
        let f2 = PacketFilter::parse(&format!("less {}", dns.len())).unwrap();
        assert!(!f2.matches(&dns));
    }
}
