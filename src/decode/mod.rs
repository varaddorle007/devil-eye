//! Protocol decoders (panic-safe on malformed input).

mod arp;
mod dhcp;
mod dns;
mod http;
mod network;
mod ssh;
mod tls;

use crate::packet::DecodedPacket;

pub use network::decode_packet;

/// Attempt application-layer enrichment after L4 decode.
pub(crate) fn enrich_app(decoded: &mut DecodedPacket, payload: &[u8]) {
    if let Some(crate::packet::TransportInfo::Udp(ref udp)) = decoded.transport {
        if !payload.is_empty() && (udp.src_port == 53 || udp.dst_port == 53) {
            if let Some(info) = dns::decode_dns(payload) {
                decoded.app = Some(crate::packet::AppInfo::Dns(info));
                return;
            }
        }
        if !payload.is_empty()
            && (udp.src_port == 67
                || udp.dst_port == 67
                || udp.src_port == 68
                || udp.dst_port == 68)
        {
            if let Some(info) = dhcp::decode_dhcp(payload) {
                decoded.app = Some(crate::packet::AppInfo::Dhcp(info));
                return;
            }
        }
    }

    if payload.is_empty() {
        return;
    }

    if let Some(crate::packet::TransportInfo::Tcp(ref tcp)) = decoded.transport {
        if let Some(info) = ssh::decode_ssh(payload) {
            decoded.app = Some(crate::packet::AppInfo::Ssh(info));
            return;
        }

        let tls_port = matches!(tcp.src_port, 443 | 8443 | 9443 | 993 | 995 | 465 | 636)
            || matches!(tcp.dst_port, 443 | 8443 | 9443 | 993 | 995 | 465 | 636);
        if tls_port || tls::looks_like_tls(payload) {
            if let Some(info) = tls::decode_tls(payload) {
                decoded.app = Some(crate::packet::AppInfo::Tls(info));
                return;
            }
        }

        let looks_http = tcp.src_port == 80
            || tcp.dst_port == 80
            || tcp.src_port == 8080
            || tcp.dst_port == 8080
            || http::looks_like_http(payload);
        if looks_http {
            if let Some(info) = http::decode_http(payload) {
                decoded.app = Some(crate::packet::AppInfo::Http(info));
            }
        }
    }
}

pub(crate) fn enrich_arp(decoded: &mut DecodedPacket, frame: &[u8]) {
    if decoded.app.is_some() {
        return;
    }
    if let Some(info) = arp::decode_arp_frame(frame) {
        decoded.app = Some(crate::packet::AppInfo::Arp(info));
        decoded.payload_len = decoded.payload_len.max(28);
    }
}
