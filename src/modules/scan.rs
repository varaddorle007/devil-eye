//! Authorized TCP connect-scan auxiliary module.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::audit::AuditLog;
use crate::cli::ScanArgs;
use crate::scope::Scope;

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub ip: String,
    pub port: u16,
    pub state: String,
    pub latency_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub ticket_id: String,
    pub operator: String,
    pub module: String,
    pub hosts_scanned: usize,
    pub ports_per_host: usize,
    pub open: Vec<PortResult>,
    pub closed_or_filtered: usize,
}

/// Run allowlisted TCP connect scan under a validated scope.
pub fn run(args: &ScanArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let audit = AuditLog::open(&args.audit_log);

    audit.info(
        "scan/tcp_connect",
        "start",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "scope_file": args.scope.display().to_string(),
            "targets": scope.targets,
            "exclude": scope.exclude,
            "ports": scope.ports,
            "max_pps": scope.max_pps,
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

    eprintln!(
        "devil-eye scan: ticket={} operator={} hosts={} ports={} max_pps={}",
        scope.ticket_id,
        scope.operator,
        hosts.len(),
        scope.ports.len(),
        scope.max_pps
    );

    for ip in &hosts {
        for &port in &scope.ports {
            // Rate limit.
            let elapsed = last_probe.elapsed();
            if elapsed < interval {
                thread::sleep(interval - elapsed);
            }
            last_probe = Instant::now();

            let started = Instant::now();
            let state = probe_tcp(*ip, port, timeout);
            let latency_ms = started.elapsed().as_millis();

            match state.as_str() {
                "open" => {
                    let row = PortResult {
                        ip: ip.to_string(),
                        port,
                        state: state.clone(),
                        latency_ms,
                    };
                    println!(
                        "{:>15}:{:<5} open  ({} ms)",
                        row.ip, row.port, row.latency_ms
                    );
                    open.push(row);
                }
                _ => {
                    closed_or_filtered += 1;
                    if args.verbose > 0 {
                        println!("{ip:>15}:{port:<5} {state}  ({latency_ms} ms)");
                    }
                }
            }
        }
    }

    let report = ScanReport {
        ticket_id: scope.ticket_id.clone(),
        operator: scope.operator.clone(),
        module: "scan/tcp_connect".into(),
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
        "scan/tcp_connect",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_common_port_classifies() {
        // We only assert the helper returns a known state — environment dependent.
        let state = probe_tcp("127.0.0.1".parse().unwrap(), 1, Duration::from_millis(200));
        assert!(state == "open" || state == "closed" || state == "filtered");
    }
}
