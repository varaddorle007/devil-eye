//! Normalized decoded packet metadata.

use std::net::IpAddr;

/// High-level view of one captured frame after decoding.
#[derive(Debug, Clone, Default)]
pub struct DecodedPacket {
    pub eth: Option<EthernetInfo>,
    pub vlan: Option<u16>,
    pub ip: Option<IpInfo>,
    pub transport: Option<TransportInfo>,
    pub app: Option<AppInfo>,
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub struct EthernetInfo {
    pub src: String,
    pub dst: String,
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub struct IpInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub version: u8,
    pub protocol: u8,
    pub ttl: Option<u8>,
    pub total_len: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum TransportInfo {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Other { protocol: u8 },
}

#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn label(self) -> String {
        let mut parts = Vec::new();
        if self.syn {
            parts.push("SYN");
        }
        if self.ack {
            parts.push("ACK");
        }
        if self.fin {
            parts.push("FIN");
        }
        if self.rst {
            parts.push("RST");
        }
        if self.psh {
            parts.push("PSH");
        }
        if self.urg {
            parts.push("URG");
        }
        if parts.is_empty() {
            ".".into()
        } else {
            parts.join(",")
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub struct IcmpInfo {
    pub version: u8,
    pub type_u8: u8,
    pub code: u8,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub enum AppInfo {
    Dns(DnsInfo),
    Http(HttpInfo),
    Ssh(SshInfo),
    Tls(TlsInfo),
    Arp(ArpInfo),
    Dhcp(DhcpInfo),
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub is_query: bool,
    pub id: u16,
    pub questions: Vec<String>,
    pub answers: Vec<String>,
    pub rcode: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub summary: String,
    pub host: Option<String>,
    pub method_or_status: String,
    /// True when Authorization / Proxy-Authorization header was present (value never stored).
    pub has_authorization: bool,
}

#[derive(Debug, Clone)]
pub struct SshInfo {
    pub banner: String,
    pub proto: String,
}

/// Passive TLS handshake fields only (no record decryption).
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub handshake: String,
    pub version: String,
    pub sni: Option<String>,
    pub cipher_suite: Option<String>,
    /// JA3 fingerprint string (ClientHello only).
    pub ja3: Option<String>,
    /// MD5 hex of `ja3` (ClientHello only).
    pub ja3_hash: Option<String>,
    /// JA3S fingerprint string (ServerHello only).
    pub ja3s: Option<String>,
    /// MD5 hex of `ja3s` (ServerHello only).
    pub ja3s_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArpInfo {
    pub operation: String,
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
}

#[derive(Debug, Clone)]
pub struct DhcpInfo {
    pub message_type: String,
    pub xid: u32,
    pub client_mac: String,
    pub client_ip: Option<String>,
    pub your_ip: Option<String>,
    pub server_ip: Option<String>,
    pub requested_ip: Option<String>,
    pub server_id: Option<String>,
    pub client_hostname: Option<String>,
}
