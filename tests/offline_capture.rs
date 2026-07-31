//! Offline PCAP integration tests (no Npcap required).

use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;

use devil_eye::capture::{OfflineSource, PcapWriter, RawPacket};
use devil_eye::cli::Args;
use devil_eye::decode::decode_packet;
use devil_eye::packet::{AppInfo, TransportInfo};
use devil_eye::stats::TrafficStats;
use etherparse::PacketBuilder;
use simple_dns::{
    rdata::{RData, A},
    Name, Packet, Question, ResourceRecord, CLASS, QCLASS, TYPE,
};
use tempfile::tempdir;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn write_pcap(path: &std::path::Path, frames: &[(u32, u32, Vec<u8>)]) {
    let mut w = PcapWriter::create(path, 65535).unwrap();
    for (sec, usec, data) in frames {
        let orig = u32::try_from(data.len()).unwrap();
        w.write_packet(&RawPacket {
            timestamp_secs: *sec,
            timestamp_usecs: *usec,
            orig_len: orig,
            data: data.clone(),
        })
        .unwrap();
    }
    w.flush().unwrap();
}

fn dns_query_payload() -> Vec<u8> {
    let mut packet = Packet::new_query(0x42);
    packet.questions.push(Question::new(
        Name::new_unchecked("example.com"),
        TYPE::A.into(),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    packet.build_bytes_vec().unwrap()
}

fn dns_response_payload() -> Vec<u8> {
    let mut packet = Packet::new_reply(0x42);
    packet.questions.push(Question::new(
        Name::new_unchecked("example.com"),
        TYPE::A.into(),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("example.com"),
        CLASS::IN,
        60,
        RData::A(A {
            address: 0x0102_0304,
        }),
    ));
    packet.build_bytes_vec().unwrap()
}

fn eth_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(src_port, dst_port);
    let mut buf = Vec::new();
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn eth_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(src_port, dst_port, 1, 64240)
        .ack(1);
    let mut buf = Vec::new();
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn tls_client_hello_sni(sni: &str) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    hello.push(1);
    hello.push(0);

    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    let list_len = (1 + 2 + name.len()) as u16;
    sni_ext.extend_from_slice(&0u16.to_be_bytes());
    let ext_data_len = (2 + list_len as usize) as u16;
    sni_ext.extend_from_slice(&ext_data_len.to_be_bytes());
    sni_ext.extend_from_slice(&list_len.to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    hello.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    hello.extend_from_slice(&sni_ext);

    let hs_len = hello.len();
    let mut hs = vec![
        1u8,
        ((hs_len >> 16) & 0xff) as u8,
        ((hs_len >> 8) & 0xff) as u8,
        (hs_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

fn arp_request_frame() -> Vec<u8> {
    let mut f = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 6, 4, 0x00, 0x01,
    ];
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    f
}

fn dhcp_discover_payload() -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&0x1111_2222u32.to_be_bytes());
    p[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    p.push(53);
    p.push(1);
    p.push(1);
    p.push(12);
    p.push(3);
    p.extend_from_slice(b"pc1");
    p.push(255);
    p
}

/// Ensure golden fixtures exist (regenerated when missing).
fn ensure_fixtures() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let dns = dir.join("dns_query.pcap");
    if !dns.exists() {
        write_pcap(
            &dns,
            &[(1_700_000_000, 0, eth_udp(53_000, 53, &dns_query_payload()))],
        );
    }

    let http = dir.join("http_get.pcap");
    if !http.exists() {
        let body = b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: secret\r\n\r\n";
        write_pcap(&http, &[(1_700_000_001, 0, eth_tcp(49_152, 80, body))]);
    }

    let ssh = dir.join("ssh_banner.pcap");
    if !ssh.exists() {
        write_pcap(
            &ssh,
            &[(
                1_700_000_003,
                0,
                eth_tcp(22, 49_200, b"SSH-2.0-OpenSSH_9.6\r\n"),
            )],
        );
    }

    let tls = dir.join("tls_clienthello.pcap");
    if !tls.exists() {
        write_pcap(
            &tls,
            &[(
                1_700_000_004,
                0,
                eth_tcp(49_300, 443, &tls_client_hello_sni("lab.example")),
            )],
        );
    }

    let arp = dir.join("arp_request.pcap");
    if !arp.exists() {
        write_pcap(&arp, &[(1_700_000_005, 0, arp_request_frame())]);
    }

    let dhcp = dir.join("dhcp_discover.pcap");
    if !dhcp.exists() {
        write_pcap(
            &dhcp,
            &[(1_700_000_006, 0, eth_udp(68, 67, &dhcp_discover_payload()))],
        );
    }

    let mixed = dir.join("mixed.pcap");
    if !mixed.exists() {
        write_pcap(
            &mixed,
            &[
                (1_700_000_002, 0, eth_udp(53_000, 53, &dns_query_payload())),
                (
                    1_700_000_002,
                    1,
                    eth_udp(53, 53_000, &dns_response_payload()),
                ),
                (
                    1_700_000_002,
                    2,
                    eth_tcp(49_152, 80, b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                ),
                (1_700_000_002, 3, vec![0xff; 8]), // malformed
            ],
        );
    }
}

#[test]
fn regenerates_and_reads_dns_fixture() {
    ensure_fixtures();
    let path = fixtures_dir().join("dns_query.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.transport {
        Some(TransportInfo::Udp(u)) => assert_eq!(u.dst_port, 53),
        _ => panic!("expected UDP"),
    }
    match decoded.app {
        Some(AppInfo::Dns(d)) => {
            assert!(d.is_query);
            assert!(!d.questions.is_empty());
        }
        _ => panic!("expected DNS"),
    }
    assert!(src.next_packet().unwrap().is_none());
}

#[test]
fn reads_pcapng_dns_fixture() {
    let path = fixtures_dir().join("dns_query.pcapng");
    assert!(path.exists(), "missing {}", path.display());
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    assert_eq!(pkt.data.len(), 71);
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.app {
        Some(AppInfo::Dns(d)) => assert!(d.is_query),
        _ => panic!("expected DNS"),
    }
    assert!(src.next_packet().unwrap().is_none());

    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "--stats",
            "-c",
            "1",
        ])
        .output()
        .expect("run capture on pcapng");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn http_fixture_redacts_secrets_in_summary() {
    ensure_fixtures();
    let path = fixtures_dir().join("http_get.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.app {
        Some(AppInfo::Http(h)) => {
            assert_eq!(h.method_or_status, "GET");
            assert_eq!(h.host.as_deref(), Some("example.com"));
            assert!(!h.summary.to_lowercase().contains("secret"));
        }
        _ => panic!("expected HTTP"),
    }
}

#[test]
fn ssh_fixture_decodes_banner() {
    ensure_fixtures();
    let path = fixtures_dir().join("ssh_banner.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.app {
        Some(AppInfo::Ssh(s)) => {
            assert_eq!(s.proto, "2.0");
            assert!(s.banner.contains("OpenSSH"));
        }
        other => panic!("expected SSH, got {other:?}"),
    }
}

#[test]
fn tls_fixture_extracts_sni() {
    ensure_fixtures();
    let path = fixtures_dir().join("tls_clienthello.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.app {
        Some(AppInfo::Tls(t)) => {
            assert_eq!(t.handshake, "client_hello");
            assert_eq!(t.sni.as_deref(), Some("lab.example"));
            assert!(t.ja3.is_some(), "expected JA3 string");
            assert_eq!(t.ja3_hash.as_ref().map(|h| h.len()), Some(32));
        }
        other => panic!("expected TLS, got {other:?}"),
    }
}

#[test]
fn arp_fixture_decodes_request() {
    ensure_fixtures();
    let path = fixtures_dir().join("arp_request.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.app {
        Some(AppInfo::Arp(a)) => {
            assert_eq!(a.operation, "request");
            assert_eq!(a.sender_ip, "10.0.0.1");
            assert_eq!(a.target_ip, "10.0.0.2");
        }
        other => panic!("expected ARP, got {other:?}"),
    }
}

#[test]
fn dhcp_fixture_decodes_discover() {
    ensure_fixtures();
    let path = fixtures_dir().join("dhcp_discover.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let pkt = src.next_packet().unwrap().unwrap();
    let decoded = decode_packet(&pkt.data).unwrap();
    match decoded.app {
        Some(AppInfo::Dhcp(d)) => {
            assert_eq!(d.message_type, "discover");
            assert_eq!(d.client_hostname.as_deref(), Some("pc1"));
        }
        other => panic!("expected DHCP, got {other:?}"),
    }
}

#[test]
fn mixed_fixture_stats_and_malformed() {
    ensure_fixtures();
    let path = fixtures_dir().join("mixed.pcap");
    let mut src = OfflineSource::open(&path).unwrap();
    let mut stats = TrafficStats::new();
    let mut failures = 0u64;
    while let Some(pkt) = src.next_packet().unwrap() {
        match decode_packet(&pkt.data) {
            Ok(d) => stats.record(&d, pkt.data.len()),
            Err(_) => {
                failures += 1;
                stats.record_raw(pkt.data.len());
            }
        }
    }
    assert_eq!(failures, 1);
    let mut buf = Cursor::new(Vec::new());
    stats.print_final(&mut buf, failures).unwrap();
    let text = String::from_utf8(buf.into_inner()).unwrap();
    assert!(text.contains("packets:"));
    assert!(text.contains("dns:"));
}

#[test]
fn pcap_roundtrip_preserves_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("roundtrip.pcap");
    let frame = eth_udp(1234, 53, &[1, 2, 3, 4]);
    write_pcap(&path, &[(10, 20, frame.clone())]);

    let mut src = OfflineSource::open(&path).unwrap();
    let got = src.next_packet().unwrap().unwrap();
    assert_eq!(got.data, frame);
    assert_eq!(got.timestamp_secs, 10);
    assert_eq!(got.timestamp_usecs, 20);
}

#[test]
fn cli_rejects_zero_count() {
    let args = Args {
        list_interfaces: false,
        interface: None,
        read: Some(PathBuf::from("x.pcap")),
        write: None,
        count: Some(0),
        filter: None,
        numeric: false,
        timestamp: 0,
        verbose: 0,
        stats: false,
        quiet: false,
        ascii: false,
        hex: false,
        link: false,
        snaplen: 65535,
        promisc: true,
        timeout_ms: 1000,
        scope: None,
        audit_log: PathBuf::from("audit.jsonl"),
    };
    assert!(args.validate().is_err());
}

#[test]
fn cli_capture_ascii_and_hex_dumps() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let path = fixtures_dir().join("http_get.pcap");
    let audit = std::env::temp_dir().join("devil-eye-dump-audit.jsonl");

    let ascii = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "-A",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run capture -A");
    assert!(
        ascii.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ascii.stderr)
    );
    let ascii_out = String::from_utf8_lossy(&ascii.stdout);
    assert!(
        ascii_out.contains("GET /") || ascii_out.contains("HTTP"),
        "ascii dump missing cleartext: {ascii_out}"
    );

    let hex = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "-X",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run capture -X");
    assert!(
        hex.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&hex.stderr)
    );
    let hex_out = String::from_utf8_lossy(&hex.stdout);
    assert!(
        hex_out.contains("0x0000:"),
        "hex dump missing offset: {hex_out}"
    );
}

#[test]
fn cli_capture_link_headers() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let path = fixtures_dir().join("dns_query.pcap");
    let audit = std::env::temp_dir().join("devil-eye-link-audit.jsonl");
    let output = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "-e",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run capture -e");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ethertype") || stdout.contains("IPv4"),
        "missing link header: {stdout}"
    );
    assert!(stdout.contains("length"), "missing length: {stdout}");
}

#[test]
fn cli_offline_filter_udp_port() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let path = fixtures_dir().join("mixed.pcap");
    let audit = std::env::temp_dir().join("devil-eye-filter-audit.jsonl");
    let output = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-f",
            "udp port 53",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run capture -f");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("udp") || stdout.contains(":53"),
        "expected UDP/DNS lines: {stdout}"
    );
    assert!(
        !stdout.contains("HTTP") && !stdout.to_lowercase().contains("tcp"),
        "TCP/HTTP should be filtered out: {stdout}"
    );
}

#[test]
fn cli_capture_writes_pcapng() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let src = fixtures_dir().join("dns_query.pcap");
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("copy.pcapng");
    let audit = std::env::temp_dir().join("devil-eye-pcapng-write-audit.jsonl");
    let output = Command::new(bin)
        .args([
            "capture",
            "-r",
            src.to_str().unwrap(),
            "-w",
            out.to_str().unwrap(),
            "-q",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run capture -w pcapng");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.exists());
    let mut reader = OfflineSource::open(&out).unwrap();
    let pkt = reader.next_packet().unwrap().unwrap();
    assert!(!pkt.data.is_empty());
    assert!(reader.next_packet().unwrap().is_none());
}

#[test]
fn cli_capture_timestamp_styles() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let path = fixtures_dir().join("dns_query.pcap");
    let audit = std::env::temp_dir().join("devil-eye-ts-audit.jsonl");

    let none = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "-t",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run -t");
    assert!(none.status.success());
    let none_out = String::from_utf8_lossy(&none.stdout);
    assert!(
        !none_out.chars().next().unwrap_or('x').is_ascii_digit(),
        "expected no leading unix ts: {none_out}"
    );

    let abs = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "-tttt",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run -tttt");
    assert!(abs.status.success());
    let abs_out = String::from_utf8_lossy(&abs.stdout);
    assert!(
        abs_out.contains('-') && abs_out.contains(':'),
        "expected absolute UTC date: {abs_out}"
    );
}

#[test]
fn cli_capture_service_port_names() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let path = fixtures_dir().join("dns_query.pcap");
    let audit = std::env::temp_dir().join("devil-eye-ports-audit.jsonl");

    let named = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run without -n");
    assert!(named.status.success());
    let named_out = String::from_utf8_lossy(&named.stdout);
    assert!(
        named_out.contains("domain"),
        "expected service name domain: {named_out}"
    );

    let numeric = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "-n",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run with -n");
    assert!(numeric.status.success());
    let num_out = String::from_utf8_lossy(&numeric.stdout);
    assert!(
        num_out.contains(".53") && !num_out.contains("domain"),
        "expected numeric port 53: {num_out}"
    );
}

#[test]
fn cli_merge_two_pcaps() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let a = fixtures_dir().join("dns_query.pcap");
    let b = fixtures_dir().join("http_get.pcap");
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("merged.pcap");
    let audit = std::env::temp_dir().join("devil-eye-merge-audit.jsonl");
    let output = Command::new(bin)
        .args([
            "merge",
            "-w",
            out.to_str().unwrap(),
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run merge");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut src = OfflineSource::open(&out).unwrap();
    assert!(src.next_packet().unwrap().is_some());
    assert!(src.next_packet().unwrap().is_some());
    assert!(src.next_packet().unwrap().is_none());
}

#[test]
fn binary_reads_fixture() {
    ensure_fixtures();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let path = fixtures_dir().join("dns_query.pcap");
    let output = Command::new(bin)
        .args([
            "capture",
            "-r",
            path.to_str().unwrap(),
            "-c",
            "1",
            "--stats",
            "--audit-log",
            std::env::temp_dir()
                .join("devil-eye-test-audit.jsonl")
                .to_str()
                .unwrap(),
        ])
        .output()
        .expect("run devil-eye");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("UDP") || stdout.contains("DNS"));
}

#[test]
fn scan_requires_authorized_scope() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut scope = NamedTempFile::new().unwrap();
    write!(
        scope,
        r#"{{
          "ticket_id": "LAB-LOCAL",
          "operator": "tester",
          "organization": "lab",
          "authorized": true,
          "targets": ["127.0.0.1"],
          "exclude": [],
          "ports": [1],
          "max_pps": 100,
          "connect_timeout_ms": 200,
          "max_hosts": 4
        }}"#
    )
    .unwrap();

    let audit = tempfile::NamedTempFile::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "scan",
            "--scope",
            scope.path().to_str().unwrap(),
            "--audit-log",
            audit.path().to_str().unwrap(),
        ])
        .output()
        .expect("run scan");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let audit_text = std::fs::read_to_string(audit.path()).unwrap();
    assert!(audit_text.contains("scan/tcp_connect"));
    assert!(audit_text.contains("LAB-LOCAL"));
}

#[test]
fn enum_requires_authorized_scope() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut scope = NamedTempFile::new().unwrap();
    write!(
        scope,
        r#"{{
          "ticket_id": "LAB-ENUM",
          "operator": "tester",
          "organization": "lab",
          "authorized": true,
          "targets": ["127.0.0.1"],
          "exclude": [],
          "ports": [1],
          "max_pps": 100,
          "connect_timeout_ms": 200,
          "max_hosts": 4
        }}"#
    )
    .unwrap();

    let audit = tempfile::NamedTempFile::new().unwrap();
    let report = tempfile::NamedTempFile::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "enum",
            "--scope",
            scope.path().to_str().unwrap(),
            "--audit-log",
            audit.path().to_str().unwrap(),
            "--json-out",
            report.path().to_str().unwrap(),
        ])
        .output()
        .expect("run enum");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let audit_text = std::fs::read_to_string(audit.path()).unwrap();
    assert!(audit_text.contains("enum/banner_tls"));
    let report_text = std::fs::read_to_string(report.path()).unwrap();
    assert!(report_text.contains("enum/banner_tls"));
}

#[test]
fn detect_flags_syn_scan_in_pcap() {
    use devil_eye::capture::{PcapWriter, RawPacket};
    use etherparse::PacketBuilder;
    use tempfile::NamedTempFile;

    let tmp = NamedTempFile::new().unwrap();
    {
        let mut w = PcapWriter::create(tmp.path(), 65535).unwrap();
        for port in 1u16..=20 {
            let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
                .ipv4([10, 0, 0, 9], [10, 0, 0, 1], 64)
                .tcp(40000, port, 1, 64240)
                .syn();
            let mut frame = Vec::new();
            builder.write(&mut frame, &[]).unwrap();
            w.write_packet(&RawPacket {
                timestamp_secs: 1_700_000_000,
                timestamp_usecs: u32::from(port),
                orig_len: frame.len() as u32,
                data: frame,
            })
            .unwrap();
        }
        w.flush().unwrap();
    }

    let audit = NamedTempFile::new().unwrap();
    let report = NamedTempFile::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "detect",
            "-r",
            tmp.path().to_str().unwrap(),
            "--syn-scan-ports",
            "10",
            "--audit-log",
            audit.path().to_str().unwrap(),
            "--json-out",
            report.path().to_str().unwrap(),
        ])
        .output()
        .expect("run detect");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report_text = std::fs::read_to_string(report.path()).unwrap();
    assert!(
        stdout.contains("tcp_syn_scan") || report_text.contains("tcp_syn_scan"),
        "stdout={stdout}\nreport={report_text}"
    );
}

#[test]
fn report_assembles_markdown_and_html() {
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    let dir = tempdir().unwrap();
    let mut scope = NamedTempFile::new_in(dir.path()).unwrap();
    write!(
        scope,
        r#"{{
          "ticket_id": "RPT-1",
          "operator": "tester",
          "organization": "lab",
          "authorized": true,
          "targets": ["127.0.0.1"],
          "exclude": [],
          "ports": [80],
          "max_pps": 10,
          "max_hosts": 4
        }}"#
    )
    .unwrap();

    let detect = dir.path().join("detect.json");
    std::fs::write(
        &detect,
        r#"{"module":"detect/ids_lite","packets":1,"alerts":[{"ts_unix_ms":1,"rule":"rare_port","severity":"medium","src":"1.2.3.4","detail":"port 31337"}]}"#,
    )
    .unwrap();

    let out_md = dir.path().join("out.md");
    let out_html = dir.path().join("out.html");
    let audit = dir.path().join("audit.jsonl");
    let pcap = fixtures_dir().join("dns_query.pcap");

    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "report",
            "--scope",
            scope.path().to_str().unwrap(),
            "--detect-json",
            detect.to_str().unwrap(),
            "--pcap",
            pcap.to_str().unwrap(),
            "--out-md",
            out_md.to_str().unwrap(),
            "--out-html",
            out_html.to_str().unwrap(),
            "--note",
            "integration test",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run report");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let md = std::fs::read_to_string(&out_md).unwrap();
    let html = std::fs::read_to_string(&out_html).unwrap();
    assert!(md.contains("RPT-1"));
    assert!(md.contains("Alerts raised"));
    assert!(html.contains("<html"));
    assert!(html.contains("RPT-1"));
    assert!(html.contains("class=\"kpis\""));
    assert!(html.contains("<svg"));
    assert!(html.contains("Timeline") || md.contains("## Timeline"));
    assert!(md.contains("Packet timeline") || html.contains("Packet timeline"));
}

#[test]
fn cli_watch_dashboard_offline() {
    let dir = tempdir().unwrap();
    let pcap = fixtures_dir().join("dns_query.pcap");
    let html = dir.path().join("live.html");
    let json = dir.path().join("dash.json");
    let audit = dir.path().join("watch-audit.jsonl");

    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "--refresh-ms",
            "50",
            "--no-clear",
            "--no-hold",
            "--html-out",
            html.to_str().unwrap(),
            "--json-out",
            json.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run watch");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Devil Eye") || stdout.contains("live dashboard"));
    assert!(html.exists());
    let snap: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(snap["module"], "watch/dashboard");
    assert!(snap["traffic"]["packets"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn cli_export_siem_cef() {
    let dir = tempdir().unwrap();
    let detect = dir.path().join("detect.json");
    std::fs::write(
        &detect,
        r#"{"module":"detect/ids_lite","packets":1,"alerts":[{"ts_unix_ms":1720000000000,"rule":"rare_port","severity":"medium","src":"10.0.0.5","detail":"dst port 4444"}]}"#,
    )
    .unwrap();
    let out = dir.path().join("alerts.cef");
    let audit = dir.path().join("export-audit.jsonl");
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "export",
            "--detect-json",
            detect.to_str().unwrap(),
            "--siem-out",
            out.to_str().unwrap(),
            "--siem-format",
            "cef",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run export");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = std::fs::read_to_string(&out).unwrap();
    assert!(body.starts_with("CEF:0|DevilEye|devil-eye|"));
    assert!(body.contains("src=10.0.0.5"));
}

#[test]
fn cli_import_suricata_eve() {
    let dir = tempdir().unwrap();
    let eve = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/eve.sample.jsonl");
    let json = dir.path().join("eve-alerts.json");
    let cef = dir.path().join("eve.cef");
    let audit = dir.path().join("import-audit.jsonl");
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "import",
            "--eve",
            eve.to_str().unwrap(),
            "--json-out",
            json.to_str().unwrap(),
            "--siem-out",
            cef.to_str().unwrap(),
            "--siem-format",
            "cef",
            "--audit-log",
            audit.to_str().unwrap(),
            "-v",
        ])
        .output()
        .expect("run import");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(report["module"], "import/suricata_eve");
    assert_eq!(report["alerts"].as_array().unwrap().len(), 2);
    assert!(report["alerts"][0]["rule"]
        .as_str()
        .unwrap()
        .starts_with("suricata:"));
    let cef_body = std::fs::read_to_string(&cef).unwrap();
    assert!(cef_body.contains("CEF:0|DevilEye|"));
}

#[test]
fn cli_import_zeek_notice() {
    let dir = tempdir().unwrap();
    let notice = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/notice.sample.log");
    let json = dir.path().join("zeek-alerts.json");
    let cef = dir.path().join("zeek.cef");
    let audit = dir.path().join("zeek-import-audit.jsonl");
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "import",
            "--zeek",
            notice.to_str().unwrap(),
            "--json-out",
            json.to_str().unwrap(),
            "--siem-out",
            cef.to_str().unwrap(),
            "--siem-format",
            "cef",
            "--audit-log",
            audit.to_str().unwrap(),
            "-v",
        ])
        .output()
        .expect("run zeek import");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(report["module"], "import/zeek_notice");
    assert_eq!(report["zeek"]["format"], "tsv");
    assert_eq!(report["alerts"].as_array().unwrap().len(), 3);
    assert!(report["alerts"][0]["rule"]
        .as_str()
        .unwrap()
        .starts_with("zeek:notice:"));
    let cef_body = std::fs::read_to_string(&cef).unwrap();
    assert!(cef_body.contains("CEF:0|DevilEye|"));
}

#[test]
fn cli_import_zeek_weird() {
    let dir = tempdir().unwrap();
    let weird = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/weird.sample.log");
    let json = dir.path().join("weird-alerts.json");
    let audit = dir.path().join("weird-import-audit.jsonl");
    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "import",
            "--zeek-weird",
            weird.to_str().unwrap(),
            "--json-out",
            json.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
            "-v",
        ])
        .output()
        .expect("run zeek weird import");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(report["module"], "import/zeek_weird");
    assert_eq!(report["zeek"]["kind"], "weird");
    assert_eq!(report["zeek"]["format"], "tsv");
    assert_eq!(report["alerts"].as_array().unwrap().len(), 3);
    assert!(report["alerts"][0]["rule"]
        .as_str()
        .unwrap()
        .starts_with("zeek:weird:"));
}

#[test]
fn cli_diff_alerts() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    let out = dir.path().join("diff.json");
    let audit = dir.path().join("diff-audit.jsonl");
    std::fs::write(
        &before,
        r#"{"module":"detect/ids_lite","alerts":[
          {"ts_unix_ms":1,"rule":"rare_port","severity":"medium","src":"1.1.1.1","detail":"4444"},
          {"ts_unix_ms":2,"rule":"tcp_syn_scan","severity":"high","src":"2.2.2.2","detail":"ports=10"}
        ]}"#,
    )
    .unwrap();
    std::fs::write(
        &after,
        r#"{"module":"detect/ids_lite","alerts":[
          {"ts_unix_ms":3,"rule":"rare_port","severity":"medium","src":"1.1.1.1","detail":"4444"},
          {"ts_unix_ms":4,"rule":"dns_nxdomain_burst","severity":"low","src":"3.3.3.3","detail":"n=8"}
        ]}"#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_devil-eye");
    let output = Command::new(bin)
        .args([
            "diff",
            "--before",
            before.to_str().unwrap(),
            "--after",
            after.to_str().unwrap(),
            "--json-out",
            out.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run diff");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tcp_syn_scan"));
    assert!(stdout.contains("dns_nxdomain_burst"));
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["module"], "diff/alerts");
    assert_eq!(report["diff"]["unchanged"], 1);
    assert_eq!(report["diff"]["only_before"].as_array().unwrap().len(), 1);
    assert_eq!(report["diff"]["only_after"].as_array().unwrap().len(), 1);

    let fail = Command::new(bin)
        .args([
            "diff",
            "--before",
            before.to_str().unwrap(),
            "--after",
            after.to_str().unwrap(),
            "--fail-on-diff",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("run diff fail-on-diff");
    assert!(!fail.status.success());
}

#[test]
fn cli_session_multi_operator() {
    let dir = tempdir().unwrap();
    let sess = dir.path().join("lab-session");
    let scope = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/scope.lab.json");
    let audit = dir.path().join("session-audit.jsonl");
    let bin = env!("CARGO_BIN_EXE_devil-eye");

    let create = Command::new(bin)
        .args([
            "session",
            "create",
            "--scope",
            scope.to_str().unwrap(),
            "--session-dir",
            sess.to_str().unwrap(),
            "--title",
            "integration",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("session create");
    assert!(
        create.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&create.stderr)
    );

    let note = Command::new(bin)
        .args([
            "session",
            "note",
            "--scope",
            scope.to_str().unwrap(),
            "--session-dir",
            sess.to_str().unwrap(),
            "--text",
            "lab check-in",
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .output()
        .expect("session note");
    assert!(note.status.success());

    let status = Command::new(bin)
        .args(["session", "status", "--session-dir", sess.to_str().unwrap()])
        .output()
        .expect("session status");
    assert!(status.status.success());
    let out = String::from_utf8_lossy(&status.stdout);
    assert!(out.contains("ticket=AUTH-LAB-0001"));
    assert!(out.contains("shared notes=1"));
}
