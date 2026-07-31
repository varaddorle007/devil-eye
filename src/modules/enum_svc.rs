//! Authorized service enumeration: banners + TLS certificate metadata.
//!
//! TLS handling only inspects the certificate presented during handshake.
//! It does NOT decrypt third-party HTTPS application data.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use native_tls::TlsConnector;
use serde::Serialize;
use x509_parser::prelude::*;

use crate::audit::AuditLog;
use crate::cli::EnumArgs;
use crate::scope::Scope;

const BANNER_MAX: usize = 512;

#[derive(Debug, Clone, Serialize)]
pub struct TlsCertMeta {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub san: Vec<String>,
    pub serial: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnumResult {
    pub ip: String,
    pub port: u16,
    pub state: String,
    pub service_guess: String,
    pub banner: Option<String>,
    pub http_server: Option<String>,
    pub tls: Option<TlsCertMeta>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnumReport {
    pub ticket_id: String,
    pub operator: String,
    pub module: String,
    pub hosts: usize,
    pub results: Vec<EnumResult>,
}

/// Run allowlisted banner + TLS-cert enumeration.
pub fn run(args: &EnumArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let audit = AuditLog::open(&args.audit_log);
    let tls_ports = parse_tls_ports(args.tls_ports.as_deref());

    audit.info(
        "enum/banner_tls",
        "start",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "scope_file": args.scope.display().to_string(),
            "targets": scope.targets,
            "ports": scope.ports,
            "tls_ports": tls_ports.iter().copied().collect::<Vec<_>>(),
            "max_pps": scope.max_pps,
        }),
        "accepted",
    )?;

    let hosts = scope.expand_hosts()?;
    let timeout = Duration::from_millis(scope.connect_timeout_ms);
    let interval = Duration::from_secs_f64(1.0 / f64::from(scope.max_pps.max(1)));
    let mut last_probe = Instant::now()
        .checked_sub(interval)
        .unwrap_or_else(Instant::now);
    let mut results = Vec::new();

    eprintln!(
        "devil-eye enum: ticket={} operator={} hosts={} ports={} (banner + TLS cert metadata)",
        scope.ticket_id,
        scope.operator,
        hosts.len(),
        scope.ports.len()
    );

    for ip in &hosts {
        for &port in &scope.ports {
            let elapsed = last_probe.elapsed();
            if elapsed < interval {
                thread::sleep(interval - elapsed);
            }
            last_probe = Instant::now();

            let row = enumerate_one(*ip, port, timeout, &tls_ports);
            print_row(&row, args.verbose > 0);
            results.push(row);
        }
    }

    let report = EnumReport {
        ticket_id: scope.ticket_id.clone(),
        operator: scope.operator.clone(),
        module: "enum/banner_tls".into(),
        hosts: hosts.len(),
        results: results.clone(),
    };

    if let Some(path) = &args.json_out {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("wrote JSON report {}", path.display());
    }

    let openish = results.iter().filter(|r| r.state == "open").count();
    writeln!(
        io::stderr(),
        "enum complete: openish={openish} total={} (audited -> {})",
        results.len(),
        audit.path().display()
    )?;

    audit.info(
        "enum/banner_tls",
        "finish",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "hosts": hosts.len(),
            "results": results.len(),
            "openish": openish,
        }),
        "ok",
    )?;

    Ok(())
}

fn parse_tls_ports(extra: Option<&str>) -> BTreeSet<u16> {
    let mut set = BTreeSet::from([443, 8443, 9443]);
    if let Some(raw) = extra {
        for part in raw.split(',') {
            if let Ok(p) = part.trim().parse::<u16>() {
                if p != 0 {
                    set.insert(p);
                }
            }
        }
    }
    set
}

fn enumerate_one(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    tls_ports: &BTreeSet<u16>,
) -> EnumResult {
    let addr = SocketAddr::new(ip, port);
    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(err) => {
            let state = if is_timeout_err(&err) {
                "filtered"
            } else {
                "closed"
            };
            return EnumResult {
                ip: ip.to_string(),
                port,
                state: state.into(),
                service_guess: "unknown".into(),
                banner: None,
                http_server: None,
                tls: None,
                error: Some(sanitize(&err.to_string())),
            };
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if tls_ports.contains(&port) {
        return enum_tls(ip, port, stream);
    }

    match port {
        80 | 8080 | 8000 | 8888 => enum_http(ip, port, stream),
        22 => enum_ssh(ip, port, stream),
        _ => enum_raw(ip, port, stream),
    }
}

fn enum_http(ip: IpAddr, port: u16, mut stream: TcpStream) -> EnumResult {
    let host = ip.to_string();
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DevilEye-Enum/0.3\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return open_err(ip, port, "http", "write failed");
    }
    let raw = read_limited(&mut stream, BANNER_MAX);
    let text = sanitize(&String::from_utf8_lossy(&raw));
    let server = extract_header(&text, "server");
    let status = text.lines().next().unwrap_or("").to_string();
    EnumResult {
        ip: ip.to_string(),
        port,
        state: "open".into(),
        service_guess: "http".into(),
        banner: Some(truncate(&status, 200)),
        http_server: server,
        tls: None,
        error: None,
    }
}

fn enum_ssh(ip: IpAddr, port: u16, mut stream: TcpStream) -> EnumResult {
    let raw = read_limited(&mut stream, 256);
    let text = sanitize(&String::from_utf8_lossy(&raw));
    let line = text.lines().next().unwrap_or("").to_string();
    EnumResult {
        ip: ip.to_string(),
        port,
        state: "open".into(),
        service_guess: "ssh".into(),
        banner: Some(truncate(&line, 200)),
        http_server: None,
        tls: None,
        error: None,
    }
}

fn enum_raw(ip: IpAddr, port: u16, mut stream: TcpStream) -> EnumResult {
    // Opportunistic read; many services stay silent until probed.
    let raw = read_limited(&mut stream, BANNER_MAX);
    let banner = if raw.is_empty() {
        None
    } else {
        Some(truncate(&sanitize(&String::from_utf8_lossy(&raw)), 200))
    };
    EnumResult {
        ip: ip.to_string(),
        port,
        state: "open".into(),
        service_guess: "tcp".into(),
        banner,
        http_server: None,
        tls: None,
        error: None,
    }
}

fn enum_tls(ip: IpAddr, port: u16, stream: TcpStream) -> EnumResult {
    let connector = match TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
    {
        Ok(c) => c,
        Err(err) => return open_err(ip, port, "tls", &err.to_string()),
    };

    // SNI uses IP string when no hostname is in scope — cert metadata still collected.
    let domain = ip.to_string();
    let tls = match connector.connect(&domain, stream) {
        Ok(t) => t,
        Err(err) => {
            return EnumResult {
                ip: ip.to_string(),
                port,
                state: "open".into(),
                service_guess: "tls?".into(),
                banner: None,
                http_server: None,
                tls: None,
                error: Some(sanitize(&format!("tls handshake failed: {err}"))),
            };
        }
    };

    let meta = match tls.peer_certificate() {
        Ok(Some(cert)) => match cert.to_der() {
            Ok(der) => parse_cert_meta(&der).ok(),
            Err(err) => {
                return open_err(ip, port, "tls", &format!("cert der: {err}"));
            }
        },
        Ok(None) => None,
        Err(err) => return open_err(ip, port, "tls", &err.to_string()),
    };

    EnumResult {
        ip: ip.to_string(),
        port,
        state: "open".into(),
        service_guess: "tls".into(),
        banner: meta
            .as_ref()
            .map(|m| format!("CN/subject={}", truncate(&m.subject, 120))),
        http_server: None,
        tls: meta,
        error: None,
    }
}

fn parse_cert_meta(der: &[u8]) -> Result<TlsCertMeta> {
    let (_, cert) = X509Certificate::from_der(der).context("x509 parse")?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let serial = cert.raw_serial_as_string();

    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            san.push(format!("{name:?}"));
            if san.len() >= 16 {
                break;
            }
        }
    }

    Ok(TlsCertMeta {
        subject: sanitize(&subject),
        issuer: sanitize(&issuer),
        not_before: sanitize(&not_before),
        not_after: sanitize(&not_after),
        san,
        serial: sanitize(&serial),
    })
}

fn open_err(ip: IpAddr, port: u16, guess: &str, err: &str) -> EnumResult {
    EnumResult {
        ip: ip.to_string(),
        port,
        state: "open".into(),
        service_guess: guess.into(),
        banner: None,
        http_server: None,
        tls: None,
        error: Some(sanitize(err)),
    }
}

fn print_row(row: &EnumResult, verbose: bool) {
    if row.state != "open" && !verbose {
        return;
    }
    let mut line = format!(
        "{:>15}:{:<5} {:<8} {}",
        row.ip, row.port, row.state, row.service_guess
    );
    if let Some(b) = &row.banner {
        line.push_str(&format!(" | {b}"));
    }
    if let Some(s) = &row.http_server {
        line.push_str(&format!(" | Server={s}"));
    }
    if let Some(tls) = &row.tls {
        line.push_str(&format!(
            " | issuer={} not_after={}",
            truncate(&tls.issuer, 60),
            tls.not_after
        ));
    }
    if let Some(err) = &row.error {
        if verbose {
            line.push_str(&format!(" | err={err}"));
        }
    }
    println!("{line}");
}

fn read_limited(stream: &mut TcpStream, max: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max];
    match stream.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

fn extract_header(text: &str, name: &str) -> Option<String> {
    let want = format!("{name}:");
    for line in text.lines() {
        if line.len() >= want.len() && line[..want.len()].eq_ignore_ascii_case(&want) {
            let v = line[want.len()..].trim();
            // Never surface auth-like headers if present.
            let lname = name.to_ascii_lowercase();
            if matches!(
                lname.as_str(),
                "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
            ) {
                return None;
            }
            return Some(sanitize(v));
        }
    }
    None
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(BANNER_MAX));
    for ch in s.chars().take(BANNER_MAX) {
        if ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control() {
            if ch == '\n' || ch == '\r' {
                out.push(' ');
            } else {
                out.push(ch);
            }
        }
    }
    out.trim().to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

fn is_timeout_err(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::TimedOut
        || err.kind() == io::ErrorKind::WouldBlock
        || err.to_string().to_lowercase().contains("timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_controls() {
        assert_eq!(sanitize("a\nb\x00c"), "a bc");
    }

    #[test]
    fn default_tls_ports_include_443() {
        let set = parse_tls_ports(None);
        assert!(set.contains(&443));
        assert!(set.contains(&8443));
    }

    #[test]
    fn extracts_server_header() {
        let text = "HTTP/1.1 200 OK\r\nServer: demo\r\n\r\n";
        assert_eq!(extract_header(text, "server").as_deref(), Some("demo"));
    }
}
