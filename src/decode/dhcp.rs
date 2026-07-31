//! DHCP / BOOTP decoder (metadata only — no lease forging).

use std::net::Ipv4Addr;

use crate::packet::DhcpInfo;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const OPT_MSG_TYPE: u8 = 53;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;
const OPT_PAD: u8 = 0;

/// Decode a DHCP message from a UDP payload (ports 67/68).
pub fn decode_dhcp(payload: &[u8]) -> Option<DhcpInfo> {
    // op..file = 236, + magic = 240
    if payload.len() < 240 {
        return None;
    }
    let op = payload[0];
    if op != 1 && op != 2 {
        return None;
    }
    if payload[236..240] != MAGIC_COOKIE {
        return None;
    }

    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ciaddr = ipv4_at(payload, 12);
    let yiaddr = ipv4_at(payload, 16);
    let siaddr = ipv4_at(payload, 20);
    let chaddr = format_chaddr(&payload[28..28 + 16], payload[2]);

    let mut message_type = "unknown".to_string();
    let mut client_hostname = None;
    let mut requested_ip = None;
    let mut server_id = None;

    let mut i = 240;
    while i < payload.len() {
        let code = payload[i];
        i += 1;
        if code == OPT_PAD {
            continue;
        }
        if code == OPT_END {
            break;
        }
        if i >= payload.len() {
            break;
        }
        let len = payload[i] as usize;
        i += 1;
        if i + len > payload.len() {
            break;
        }
        let data = &payload[i..i + len];
        match code {
            OPT_MSG_TYPE if !data.is_empty() => {
                message_type = dhcp_msg_type(data[0]).into();
            }
            OPT_HOSTNAME => {
                if let Ok(s) = std::str::from_utf8(data) {
                    let s = s.trim_matches(char::from(0)).trim();
                    if !s.is_empty() && s.len() <= 255 {
                        client_hostname = Some(s.to_string());
                    }
                }
            }
            OPT_REQUESTED_IP if data.len() == 4 => {
                requested_ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string());
            }
            OPT_SERVER_ID if data.len() == 4 => {
                server_id = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string());
            }
            _ => {}
        }
        i += len;
    }

    Some(DhcpInfo {
        message_type,
        xid,
        client_mac: chaddr,
        client_ip: nonzero_ip(ciaddr),
        your_ip: nonzero_ip(yiaddr),
        server_ip: nonzero_ip(siaddr),
        requested_ip,
        server_id,
        client_hostname,
    })
}

fn ipv4_at(buf: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3])
}

fn nonzero_ip(ip: Ipv4Addr) -> Option<String> {
    if ip.is_unspecified() {
        None
    } else {
        Some(ip.to_string())
    }
}

fn format_chaddr(chaddr: &[u8], hlen: u8) -> String {
    let n = usize::from(hlen).clamp(0, 16).min(chaddr.len());
    if n == 0 {
        return String::new();
    }
    chaddr[..n]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn dhcp_msg_type(t: u8) -> &'static str {
    match t {
        1 => "discover",
        2 => "offer",
        3 => "request",
        4 => "decline",
        5 => "ack",
        6 => "nak",
        7 => "release",
        8 => "inform",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dhcp_discover() -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // BOOTREQUEST
        p[1] = 1; // ethernet
        p[2] = 6; // hlen
        p[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        p[28..34].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        p[236..240].copy_from_slice(&MAGIC_COOKIE);
        // options: type=discover, hostname, end
        p.push(OPT_MSG_TYPE);
        p.push(1);
        p.push(1);
        p.push(OPT_HOSTNAME);
        p.push(4);
        p.extend_from_slice(b"lab1");
        p.push(OPT_END);
        p
    }

    #[test]
    fn decodes_discover_with_hostname() {
        let info = decode_dhcp(&dhcp_discover()).expect("dhcp");
        assert_eq!(info.message_type, "discover");
        assert_eq!(info.xid, 0xdead_beef);
        assert_eq!(info.client_mac, "11:22:33:44:55:66");
        assert_eq!(info.client_hostname.as_deref(), Some("lab1"));
    }
}
