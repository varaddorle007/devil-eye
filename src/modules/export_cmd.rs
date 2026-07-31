//! Offline SIEM conversion from detect JSON reports.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::audit::AuditLog;
use crate::cli::ExportArgs;
use crate::detect::Alert;
use crate::siem::{SiemExporter, SiemFormat, SiemMeta};

#[derive(Debug, Deserialize)]
struct DetectJson {
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    alerts: Vec<Alert>,
}

/// Convert a detect JSON report into SIEM lines (file and/or UDP).
pub fn run(args: &ExportArgs) -> Result<()> {
    let format = SiemFormat::parse(&args.siem_format)?;
    if args.siem_out.is_none() && args.siem_udp.is_none() {
        bail!("export requires --siem-out and/or --siem-udp");
    }

    let (operator, ticket) = if let Some(path) = &args.scope {
        let scope = crate::scope::Scope::load(path)?;
        (scope.operator, scope.ticket_id)
    } else {
        ("anonymous".into(), "export-no-scope".into())
    };

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "export/siem",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "detect_json": args.detect_json.display().to_string(),
            "siem_format": format.as_str(),
            "siem_out": args.siem_out.as_ref().map(|p| p.display().to_string()),
            "siem_udp": args.siem_udp,
        }),
        "ok",
    )?;

    let raw = std::fs::read_to_string(&args.detect_json)
        .with_context(|| format!("failed to read {}", args.detect_json.display()))?;
    let report: DetectJson = serde_json::from_str(&raw)
        .with_context(|| format!("invalid detect JSON {}", args.detect_json.display()))?;

    let module = report.module.unwrap_or_else(|| "detect/ids_lite".into());
    let meta = SiemMeta::new(module, operator.clone(), ticket.clone());
    let mut exporter = SiemExporter::open(
        format,
        meta,
        args.siem_out.as_deref(),
        args.siem_udp.as_deref(),
    )?;
    exporter.emit_many(&report.alerts)?;
    exporter.flush()?;

    writeln!(
        io::stderr(),
        "export complete: alerts={} format={} emitted={} (audited -> {})",
        report.alerts.len(),
        format.as_str(),
        exporter.emitted(),
        audit.path().display()
    )?;

    audit.info(
        "export/siem",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "alerts": report.alerts.len(),
            "emitted": exporter.emitted(),
            "format": format.as_str(),
        }),
        "ok",
    )?;

    Ok(())
}

/// Shared helper to build an exporter from detect/watch CLI flags.
pub fn maybe_open_from_flags(
    module: &str,
    operator: &str,
    ticket: &str,
    format: &str,
    out: Option<&PathBuf>,
    udp: Option<&str>,
) -> Result<Option<SiemExporter>> {
    if out.is_none() && udp.is_none() {
        return Ok(None);
    }
    let fmt = SiemFormat::parse(format)?;
    let meta = SiemMeta::new(module, operator, ticket);
    Ok(Some(SiemExporter::open(
        fmt,
        meta,
        out.map(PathBuf::as_path),
        udp,
    )?))
}
