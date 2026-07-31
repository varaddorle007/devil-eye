//! L2–L4 decoding via etherparse (no panics on truncated frames).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::decode::{enrich_app, enrich_arp};
use crate::packet::{
    DecodedPacket, EthernetInfo, IcmpInfo, IpInfo, TcpFlags, TcpInfo, TransportInfo, UdpInfo,
};

/// Decode an Ethernet frame into structured metadata.
pub fn decode_packet(frame: &[u8]) -> Result<DecodedPacket> {
    let sliced = SlicedPacket::from_ethernet(frame).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut decoded = DecodedPacket::default();

    if let Some(etherparse::LinkSlice::Ethernet2(eth)) = sliced.link {
        decoded.eth = Some(EthernetInfo {
            src: format_mac(eth.source()),
            dst: format_mac(eth.destination()),
            ethertype: u16::from(eth.ether_type()),
        });
    }

    if let Some(vlan) = sliced.vlan {
        match vlan {
            etherparse::VlanSlice::SingleVlan(v) => {
                decoded.vlan = Some(u16::from(v.vlan_identifier()));
            }
            etherparse::VlanSlice::DoubleVlan(v) => {
                decoded.vlan = Some(u16::from(v.outer().vlan_identifier()));
            }
        }
    }

    let mut payload: &[u8] = &[];

    if let Some(net) = sliced.net {
        match net {
            NetSlice::Ipv4(ipv4) => {
                let hdr = ipv4.header();
                decoded.ip = Some(IpInfo {
                    src: IpAddr::V4(Ipv4Addr::from(hdr.source())),
                    dst: IpAddr::V4(Ipv4Addr::from(hdr.destination())),
                    version: 4,
                    protocol: u8::from(hdr.protocol()),
                    ttl: Some(hdr.ttl()),
                    total_len: Some(hdr.total_len()),
                });
                payload = ipv4.payload().payload;
            }
            NetSlice::Ipv6(ipv6) => {
                let hdr = ipv6.header();
                decoded.ip = Some(IpInfo {
                    src: IpAddr::V6(Ipv6Addr::from(hdr.source())),
                    dst: IpAddr::V6(Ipv6Addr::from(hdr.destination())),
                    version: 6,
                    protocol: u8::from(hdr.next_header()),
                    ttl: Some(hdr.hop_limit()),
                    total_len: Some(
                        u16::try_from(ipv6.payload().payload.len().saturating_add(40))
                            .unwrap_or(u16::MAX),
                    ),
                });
                payload = ipv6.payload().payload;
            }
        }
    }

    if let Some(transport) = sliced.transport {
        match transport {
            TransportSlice::Tcp(tcp) => {
                let info = TcpInfo {
                    src_port: tcp.source_port(),
                    dst_port: tcp.destination_port(),
                    seq: tcp.sequence_number(),
                    ack: tcp.acknowledgment_number(),
                    flags: TcpFlags {
                        syn: tcp.syn(),
                        ack: tcp.ack(),
                        fin: tcp.fin(),
                        rst: tcp.rst(),
                        psh: tcp.psh(),
                        urg: tcp.urg(),
                    },
                    window: tcp.window_size(),
                    payload_len: tcp.payload().len(),
                };
                payload = tcp.payload();
                decoded.payload_len = info.payload_len;
                decoded.transport = Some(TransportInfo::Tcp(info));
            }
            TransportSlice::Udp(udp) => {
                let info = UdpInfo {
                    src_port: udp.source_port(),
                    dst_port: udp.destination_port(),
                    length: udp.length(),
                    payload_len: udp.payload().len(),
                };
                payload = udp.payload();
                decoded.payload_len = info.payload_len;
                decoded.transport = Some(TransportInfo::Udp(info));
            }
            TransportSlice::Icmpv4(icmp) => {
                let type_u8 = icmp.type_u8();
                let code = icmp.code_u8();
                decoded.transport = Some(TransportInfo::Icmp(IcmpInfo {
                    version: 4,
                    type_u8,
                    code,
                    summary: icmpv4_summary(type_u8, code),
                }));
            }
            TransportSlice::Icmpv6(icmp) => {
                let type_u8 = icmp.type_u8();
                let code = icmp.code_u8();
                decoded.transport = Some(TransportInfo::Icmp(IcmpInfo {
                    version: 6,
                    type_u8,
                    code,
                    summary: icmpv6_summary(type_u8, code),
                }));
            }
        }
    } else if let Some(ip) = &decoded.ip {
        decoded.transport = Some(TransportInfo::Other {
            protocol: ip.protocol,
        });
    }

    if decoded.eth.is_none() && decoded.ip.is_none() {
        bail!("unsupported or empty frame");
    }

    enrich_app(&mut decoded, payload);
    enrich_arp(&mut decoded, frame);
    Ok(decoded)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn icmpv4_summary(type_u8: u8, code: u8) -> String {
    let name = match type_u8 {
        0 => "echo-reply",
        3 => "dest-unreach",
        8 => "echo-request",
        11 => "time-exceeded",
        _ => "icmp",
    };
    format!("{name} type={type_u8} code={code}")
}

fn icmpv6_summary(type_u8: u8, code: u8) -> String {
    let name = match type_u8 {
        1 => "dest-unreach",
        128 => "echo-request",
        129 => "echo-reply",
        133 => "router-solicit",
        134 => "router-advert",
        135 => "neighbor-solicit",
        136 => "neighbor-advert",
        _ => "icmp6",
    };
    format!("{name} type={type_u8} code={code}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    #[test]
    fn decodes_udp_dns_ports() {
        let builder = PacketBuilder::ethernet2([0; 6], [1; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(53, 53_000);
        let payload = [0u8; 12];
        let mut buf = Vec::new();
        builder.write(&mut buf, &payload).unwrap();

        let decoded = decode_packet(&buf).unwrap();
        assert!(decoded.ip.is_some());
        match decoded.transport {
            Some(TransportInfo::Udp(u)) => {
                assert_eq!(u.src_port, 53);
                assert_eq!(u.dst_port, 53_000);
            }
            _ => panic!("expected UDP"),
        }
    }

    #[test]
    fn decodes_arp_request_frame() {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x06,
            0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01,
        ];
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 2]);

        let decoded = decode_packet(&frame).unwrap();
        match decoded.app {
            Some(crate::packet::AppInfo::Arp(a)) => {
                assert_eq!(a.operation, "request");
                assert_eq!(a.target_ip, "10.0.0.2");
            }
            other => panic!("expected ARP, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(decode_packet(&[]).is_err());
    }
}
