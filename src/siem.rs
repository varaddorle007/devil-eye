//! SIEM alert connectors: JSONL, CEF, and syslog line formats (+ optional UDP).

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::detect::Alert;

/// Wire format for exported alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    /// Newline-delimited JSON (Splunk / Elastic / generic).
    Jsonl,
    /// ArcSight Common Event Format.
    Cef,
    /// RFC5424-style syslog (APP-NAME=devil-eye).
    Syslog,
}

impl SiemFormat {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "jsonl" | "ndjson" | "json" => Ok(Self::Jsonl),
            "cef" => Ok(Self::Cef),
            "syslog" | "rfc5424" => Ok(Self::Syslog),
            other => bail!("siem format must be jsonl|cef|syslog (got {other})"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Cef => "cef",
            Self::Syslog => "syslog",
        }
    }
}

/// Context stamped onto every exported event.
#[derive(Debug, Clone, Default)]
pub struct SiemMeta {
    pub ticket_id: String,
    pub operator: String,
    pub module: String,
    pub hostname: String,
}

impl SiemMeta {
    pub fn new(
        module: impl Into<String>,
        operator: impl Into<String>,
        ticket: impl Into<String>,
    ) -> Self {
        Self {
            ticket_id: ticket.into(),
            operator: operator.into(),
            module: module.into(),
            hostname: hostname(),
        }
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "devil-eye".into())
}

fn product_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Streaming exporter: file and/or UDP destination.
pub struct SiemExporter {
    format: SiemFormat,
    meta: SiemMeta,
    file: Option<BufWriter<File>>,
    udp: Option<(UdpSocket, SocketAddr)>,
    emitted: u64,
}

impl SiemExporter {
    pub fn open(
        format: SiemFormat,
        meta: SiemMeta,
        path: Option<&Path>,
        udp_addr: Option<&str>,
    ) -> Result<Self> {
        if path.is_none() && udp_addr.is_none() {
            bail!("SIEM export requires --siem-out and/or --siem-udp");
        }

        let file = match path {
            Some(p) => {
                let f = File::create(p)
                    .with_context(|| format!("failed to create SIEM output {}", p.display()))?;
                Some(BufWriter::new(f))
            }
            None => None,
        };

        let udp = match udp_addr {
            Some(raw) => Some(bind_udp(raw)?),
            None => None,
        };

        Ok(Self {
            format,
            meta,
            file,
            udp,
            emitted: 0,
        })
    }

    pub fn format(&self) -> SiemFormat {
        self.format
    }

    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    pub fn emit(&mut self, alert: &Alert) -> Result<()> {
        let line = format_alert(self.format, alert, &self.meta);
        if let Some(w) = self.file.as_mut() {
            writeln!(w, "{line}")?;
        }
        if let Some((sock, dest)) = self.udp.as_ref() {
            let payload = line.as_bytes();
            // UDP practical limit; truncate rather than fail the run.
            let bytes = if payload.len() > 1200 {
                &payload[..1200]
            } else {
                payload
            };
            sock.send_to(bytes, dest)
                .with_context(|| format!("SIEM UDP send to {dest} failed"))?;
        }
        self.emitted += 1;
        Ok(())
    }

    pub fn emit_many(&mut self, alerts: &[Alert]) -> Result<()> {
        for a in alerts {
            self.emit(a)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        if let Some(w) = self.file.as_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

fn bind_udp(raw: &str) -> Result<(UdpSocket, SocketAddr)> {
    let mut addrs = raw
        .to_socket_addrs()
        .with_context(|| format!("invalid --siem-udp address: {raw}"))?;
    let dest = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve --siem-udp address: {raw}"))?;
    let bind = if dest.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).context("failed to bind SIEM UDP socket")?;
    sock.set_write_timeout(Some(Duration::from_secs(2))).ok();
    Ok((sock, dest))
}

/// Format one alert without I/O (for tests / offline conversion).
pub fn format_alert(format: SiemFormat, alert: &Alert, meta: &SiemMeta) -> String {
    match format {
        SiemFormat::Jsonl => format_jsonl(alert, meta),
        SiemFormat::Cef => format_cef(alert, meta),
        SiemFormat::Syslog => format_syslog(alert, meta),
    }
}

#[derive(Serialize)]
struct JsonlEvent<'a> {
    ts_unix_ms: u64,
    product: &'static str,
    version: &'static str,
    module: &'a str,
    ticket_id: &'a str,
    operator: &'a str,
    rule: &'a str,
    severity: &'a str,
    src: &'a str,
    detail: &'a str,
    hostname: &'a str,
}

fn format_jsonl(alert: &Alert, meta: &SiemMeta) -> String {
    let ev = JsonlEvent {
        ts_unix_ms: alert.ts_unix_ms,
        product: "devil-eye",
        version: product_version(),
        module: &meta.module,
        ticket_id: &meta.ticket_id,
        operator: &meta.operator,
        rule: &alert.rule,
        severity: &alert.severity,
        src: &alert.src,
        detail: &alert.detail,
        hostname: &meta.hostname,
    };
    serde_json::to_string(&ev).unwrap_or_else(|_| {
        format!(
            r#"{{"rule":"{}","severity":"{}","src":"{}"}}"#,
            alert.rule, alert.severity, alert.src
        )
    })
}

fn cef_severity(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "info" => 2,
        "low" => 3,
        "medium" => 5,
        "high" => 7,
        "critical" => 9,
        _ => 5,
    }
}

fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

fn format_cef(alert: &Alert, meta: &SiemMeta) -> String {
    let sev = cef_severity(&alert.severity);
    let name = cef_escape(&alert.rule);
    let detail = cef_escape(&alert.detail);
    let src = cef_escape(&alert.src);
    format!(
        "CEF:0|DevilEye|devil-eye|{ver}|{sig}|{name}|{sev}|rt={rt} src={src} msg={detail} cs1Label=ticket cs1={ticket} cs2Label=operator cs2={op} cs3Label=module cs3={module}",
        ver = product_version(),
        sig = cef_escape(&alert.rule),
        name = name,
        sev = sev,
        rt = alert.ts_unix_ms,
        src = src,
        detail = detail,
        ticket = cef_escape(&meta.ticket_id),
        op = cef_escape(&meta.operator),
        module = cef_escape(&meta.module),
    )
}

fn format_syslog(alert: &Alert, meta: &SiemMeta) -> String {
    // facility=local0 (16), severity mapped roughly to syslog severity
    let pri = 16 * 8
        + match alert.severity.to_ascii_lowercase().as_str() {
            "critical" => 2u8,
            "high" => 3,
            "medium" => 4,
            "low" => 5,
            _ => 6,
        };
    let ts = rfc3339_from_ms(alert.ts_unix_ms);
    let msg = format!(
        "rule={} severity={} src={} ticket={} operator={} detail={}",
        syslog_token(&alert.rule),
        syslog_token(&alert.severity),
        syslog_token(&alert.src),
        syslog_token(&meta.ticket_id),
        syslog_token(&meta.operator),
        syslog_msg(&alert.detail),
    );
    format!(
        "<{pri}>1 {ts} {host} devil-eye {module} - - {msg}",
        pri = pri,
        ts = ts,
        host = syslog_token(&meta.hostname),
        module = syslog_token(&meta.module),
        msg = msg,
    )
}

fn syslog_token(s: &str) -> String {
    let t = s.replace([' ', '\t', '\n', '\r'], "_");
    if t.is_empty() {
        "-".into()
    } else {
        t
    }
}

fn syslog_msg(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn rfc3339_from_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs / 86_400;
    let day_secs = secs % 86_400;
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Howard Hinnant civil_from_days (proleptic Gregorian), days since Unix epoch.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Open a streaming exporter when at least one destination is configured.
pub fn maybe_exporter(
    format: &str,
    meta: SiemMeta,
    out: Option<&Path>,
    udp: Option<&str>,
) -> Result<Option<SiemExporter>> {
    if out.is_none() && udp.is_none() {
        return Ok(None);
    }
    let fmt = SiemFormat::parse(format)?;
    Ok(Some(SiemExporter::open(fmt, meta, out, udp)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Alert, SiemMeta) {
        (
            Alert {
                ts_unix_ms: 1_720_000_000_000,
                rule: "rare_port".into(),
                severity: "medium".into(),
                src: "10.0.0.5".into(),
                detail: "dst port 4444".into(),
            },
            SiemMeta::new("detect/ids_lite", "alice", "T-1"),
        )
    }

    #[test]
    fn jsonl_round_fields() {
        let (a, m) = sample();
        let line = format_alert(SiemFormat::Jsonl, &a, &m);
        assert!(line.contains("\"rule\":\"rare_port\""));
        assert!(line.contains("\"ticket_id\":\"T-1\""));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn cef_has_header() {
        let (a, m) = sample();
        let line = format_alert(SiemFormat::Cef, &a, &m);
        assert!(line.starts_with("CEF:0|DevilEye|devil-eye|"));
        assert!(line.contains("src=10.0.0.5"));
        assert!(line.contains("cs1=T-1"));
    }

    #[test]
    fn syslog_has_pri() {
        let (a, m) = sample();
        let line = format_alert(SiemFormat::Syslog, &a, &m);
        assert!(line.starts_with('<'));
        assert!(line.contains("devil-eye"));
        assert!(line.contains("rule=rare_port"));
    }

    #[test]
    fn cef_escapes_pipes() {
        let (mut a, m) = sample();
        a.detail = "a|b=c".into();
        let line = format_alert(SiemFormat::Cef, &a, &m);
        assert!(line.contains("msg=a\\|b\\=c"));
    }

    #[test]
    fn writes_jsonl_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let (a, m) = sample();
        let mut exp = SiemExporter::open(SiemFormat::Jsonl, m, Some(&path), None).unwrap();
        exp.emit(&a).unwrap();
        exp.flush().unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("rare_port"));
        assert_eq!(exp.emitted(), 1);
    }
}
