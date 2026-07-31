//! Authorized TCP/UDP probe auxiliary module (connect / datagram — no exploits).

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::audit::AuditLog;
use crate::cli::{ScanArgs, ScanProto};
use crate::scope::Scope;

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub ip: String,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub latency_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub ticket_id: String,
    pub operator: String,
    pub module: String,
    pub proto: String,
    pub hosts_scanned: usize,
    pub ports_per_host: usize,
    pub open: Vec<PortResult>,
    pub closed_or_filtered: usize,
}

/// Run allowlisted TCP connect and/or UDP datagram probes under a validated scope.
pub fn run(args: &ScanArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let audit = AuditLog::open(&args.audit_log);
    let module = match args.proto {
        ScanProto::Tcp => "scan/tcp_connect",
        ScanProto::Udp => "scan/udp_probe",
        ScanProto::Both => "scan/tcp_udp",
    };

    audit.info(
        module,
        "start",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "scope_file": args.scope.display().to_string(),
            "targets": scope.targets,
            "exclude": scope.exclude,
            "ports": scope.ports,
            "max_pps": scope.max_pps,
            "proto": format!("{:?}", args.proto).to_ascii_lowercase(),
        }),
        "accepted",
    )?;

    let hosts = scope.expand_hosts()?;
    let timeout = Duration::from_millis(scope.connect_timeout_ms);
    let interval = Duration::from_secs_f64(1.0 / f64::from(scope.max_pps.max(1)));

    let mut open = Vec::new();
    let mut closed_or_filtered = 0usize;
    let mut last_probe = Instant::now()
        .checked_sub(interval)
        .unwrap_or_else(Instant::now);

    let protos: &[&str] = match args.proto {
        ScanProto::Tcp => &["tcp"],
        ScanProto::Udp => &["udp"],
        ScanProto::Both => &["tcp", "udp"],
    };

    eprintln!(
        "devil-eye scan: ticket={} operator={} hosts={} ports={} proto={:?} max_pps={}",
        scope.ticket_id,
        scope.operator,
        hosts.len(),
        scope.ports.len(),
        args.proto,
        scope.max_pps
    );

    for ip in &hosts {
        for &port in &scope.ports {
            for &proto in protos {
                let elapsed = last_probe.elapsed();
                if elapsed < interval {
                    thread::sleep(interval - elapsed);
                }
                last_probe = Instant::now();

                let started = Instant::now();
                let state = match proto {
                    "tcp" => probe_tcp(*ip, port, timeout),
                    _ => probe_udp(*ip, port, timeout),
                };
                let latency_ms = started.elapsed().as_millis();

                match (proto, state.as_str()) {
                    ("tcp", "open") | ("udp", "open") => {
                        let row = PortResult {
                            ip: ip.to_string(),
                            port,
                            proto: proto.into(),
                            state: state.clone(),
                            latency_ms,
                        };
                        println!(
                            "{:>15}:{:<5}/{:<3} {}  ({} ms)",
                            row.ip, row.port, row.proto, row.state, row.latency_ms
                        );
                        open.push(row);
                    }
                    ("udp", "open|filtered") => {
                        closed_or_filtered += 1;
                        if args.verbose > 0 {
                            println!("{ip:>15}:{port:<5}/udp open|filtered  ({latency_ms} ms)");
                        }
                    }
                    _ => {
                        closed_or_filtered += 1;
                        if args.verbose > 0 {
                            println!("{ip:>15}:{port:<5}/{proto} {state}  ({latency_ms} ms)");
                        }
                    }
                }
            }
        }
    }

    let report = ScanReport {
        ticket_id: scope.ticket_id.clone(),
        operator: scope.operator.clone(),
        module: module.into(),
        proto: format!("{:?}", args.proto).to_ascii_lowercase(),
        hosts_scanned: hosts.len(),
        ports_per_host: scope.ports.len(),
        open: open.clone(),
        closed_or_filtered,
    };

    if let Some(path) = &args.json_out {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("wrote JSON report {}", path.display());
    }

    writeln!(
        io::stderr(),
        "scan complete: open={} closed_or_filtered={} (audited -> {})",
        open.len(),
        closed_or_filtered,
        audit.path().display()
    )?;

    audit.info(
        module,
        "finish",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "hosts_scanned": report.hosts_scanned,
            "open_count": open.len(),
            "closed_or_filtered": closed_or_filtered,
        }),
        "ok",
    )?;

    Ok(())
}

fn probe_tcp(ip: IpAddr, port: u16, timeout: Duration) -> String {
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => "open".into(),
        Err(err) => {
            let kind = err.kind();
            if kind == io::ErrorKind::TimedOut
                || kind == io::ErrorKind::WouldBlock
                || err.to_string().to_lowercase().contains("timed out")
            {
                "filtered".into()
            } else {
                "closed".into()
            }
        }
    }
}

/// Best-effort UDP probe: reply => open; timeout => open|filtered (ICMP often not visible).
fn probe_udp(ip: IpAddr, port: u16, timeout: Duration) -> String {
    let Ok(sock) = UdpSocket::bind(SocketAddr::new(
        if ip.is_ipv4() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            IpAddr::from([0u8; 16])
        },
        0,
    )) else {
        return "error".into();
    };
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    let dest = SocketAddr::new(ip, port);
    // Empty or tiny payload — not a protocol exploit, just a datagram.
    if sock.send_to(&[0u8; 1], dest).is_err() {
        return "closed".into();
    }
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok(_) => "open".into(),
        Err(err) => {
            let kind = err.kind();
            if kind == io::ErrorKind::TimedOut
                || kind == io::ErrorKind::WouldBlock
                || err.to_string().to_lowercase().contains("timed out")
            {
                "open|filtered".into()
            } else if kind == io::ErrorKind::ConnectionRefused {
                "closed".into()
            } else {
                "open|filtered".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_common_port_classifies() {
        let state = probe_tcp("127.0.0.1".parse().unwrap(), 1, Duration::from_millis(200));
        assert!(state == "open" || state == "closed" || state == "filtered");
    }

    #[test]
    fn localhost_udp_probe_returns_known_state() {
        let state = probe_udp("127.0.0.1".parse().unwrap(), 1, Duration::from_millis(150));
        assert!(
            state == "open"
                || state == "closed"
                || state == "open|filtered"
                || state == "error"
        );
    }
}
