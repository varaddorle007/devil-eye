//! ARP decoder (Ethernet/IPv4 only).

use std::net::Ipv4Addr;

use crate::packet::ArpInfo;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;

/// Locate and decode an ARP payload inside an Ethernet (+ optional VLAN) frame.
pub fn decode_arp_frame(frame: &[u8]) -> Option<ArpInfo> {
    let (ethertype, payload_off) = ethertype_and_payload_offset(frame)?;
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    decode_arp_body(frame.get(payload_off..)?)
}

fn ethertype_and_payload_offset(frame: &[u8]) -> Option<(u16, usize)> {
    if frame.len() < 14 {
        return None;
    }
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    if et == ETHERTYPE_VLAN {
        if frame.len() < 18 {
            return None;
        }
        Some((u16::from_be_bytes([frame[16], frame[17]]), 18))
    } else {
        Some((et, 14))
    }
}

fn decode_arp_body(body: &[u8]) -> Option<ArpInfo> {
    if body.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([body[0], body[1]]);
    let ptype = u16::from_be_bytes([body[2], body[3]]);
    let hlen = body[4];
    let plen = body[5];
    let oper = u16::from_be_bytes([body[6], body[7]]);
    // Ethernet + IPv4 only.
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
        return None;
    }

    let sender_mac = format_mac(&body[8..14]);
    let sender_ip = Ipv4Addr::new(body[14], body[15], body[16], body[17]).to_string();
    let target_mac = format_mac(&body[18..24]);
    let target_ip = Ipv4Addr::new(body[24], body[25], body[26], body[27]).to_string();

    let operation = match oper {
        1 => "request",
        2 => "reply",
        other => {
            return Some(ArpInfo {
                operation: format!("op-{other}"),
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
            })
        }
    };

    Some(ArpInfo {
        operation: operation.into(),
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_request_frame() -> Vec<u8> {
        let mut f = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x08, 0x06, // ARP
            0x00, 0x01, // htype eth
            0x08, 0x00, // ptype ipv4
            6, 4, // lens
            0x00, 0x01, // request
        ];
        f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // sha
        f.extend_from_slice(&[10, 0, 0, 1]); // spa
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // tha
        f.extend_from_slice(&[10, 0, 0, 2]); // tpa
        f
    }

    #[test]
    fn decodes_arp_request() {
        let info = decode_arp_frame(&arp_request_frame()).expect("arp");
        assert_eq!(info.operation, "request");
        assert_eq!(info.sender_ip, "10.0.0.1");
        assert_eq!(info.target_ip, "10.0.0.2");
        assert_eq!(info.sender_mac, "aa:bb:cc:dd:ee:ff");
    }
}
