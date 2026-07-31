//! Import Suricata EVE JSONL or Zeek notice/weird logs into Devil Eye detect-compatible alerts.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::audit::AuditLog;
use crate::cli::ImportArgs;
use crate::detect::Alert;
use crate::eve::{import_eve_file, EveImportOpts};
use crate::modules::export_cmd;
use crate::zeek::{import_zeek_file, ZeekImportOpts, ZeekLogKind};

#[derive(Debug, Serialize)]
struct ImportReport {
    module: String,
    source: String,
    packets: u64,
    alerts: Vec<Alert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eve: Option<EveStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zeek: Option<ZeekStats>,
}

#[derive(Debug, Serialize)]
struct EveStats {
    lines_read: u64,
    alerts_kept: u64,
    skipped: u64,
    parse_errors: u64,
    truncated: bool,
    event_types: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ZeekStats {
    kind: String,
    lines_read: u64,
    alerts_kept: u64,
    skipped: u64,
    parse_errors: u64,
    truncated: bool,
    format: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    note_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    weird_names: Vec<String>,
}

struct Converted {
    module: &'static str,
    source: PathBuf,
    alerts: Vec<Alert>,
    lines_read: u64,
    alerts_kept: u64,
    skipped: u64,
    parse_errors: u64,
    truncated: bool,
    eve: Option<EveStats>,
    zeek: Option<ZeekStats>,
}

/// Run Suricata EVE or Zeek notice/weird → Devil Eye alert import.
pub fn run(args: &ImportArgs) -> Result<()> {
    if args.json_out.is_none() && args.siem_out.is_none() && args.siem_udp.is_none() {
        bail!("import requires --json-out and/or --siem-out/--siem-udp");
    }
    if args.eve.is_none() && args.zeek.is_none() && args.zeek_weird.is_none() {
        bail!("import requires --eve <file>, --zeek <file>, or --zeek-weird <file>");
    }

    let (operator, ticket) = if let Some(path) = &args.scope {
        let scope = crate::scope::Scope::load(path)?;
        (scope.operator, scope.ticket_id)
    } else {
        ("anonymous".into(), "import-no-scope".into())
    };

    let converted = if let Some(eve_path) = &args.eve {
        convert_eve(args, eve_path)?
    } else if let Some(zeek_path) = &args.zeek {
        convert_zeek(args, zeek_path, ZeekLogKind::Notice)?
    } else if let Some(weird_path) = &args.zeek_weird {
        convert_zeek(args, weird_path, ZeekLogKind::Weird)?
    } else {
        unreachable!("validated above");
    };

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        converted.module,
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "source": converted.source.display().to_string(),
            "max_alerts": args.max_alerts,
            "json_out": args.json_out.as_ref().map(|p| p.display().to_string()),
            "siem_format": args.siem_format,
            "siem_out": args.siem_out.as_ref().map(|p| p.display().to_string()),
            "siem_udp": args.siem_udp,
            "eve": args.eve.as_ref().map(|p| p.display().to_string()),
            "zeek": args.zeek.as_ref().map(|p| p.display().to_string()),
            "zeek_weird": args.zeek_weird.as_ref().map(|p| p.display().to_string()),
        }),
        "ok",
    )?;

    let report = ImportReport {
        module: converted.module.into(),
        source: converted.source.display().to_string(),
        packets: 0,
        alerts: converted.alerts.clone(),
        eve: converted.eve,
        zeek: converted.zeek,
    };

    if let Some(path) = &args.json_out {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("wrote detect-compatible JSON {}", path.display());
    }

    let mut siem = export_cmd::maybe_open_from_flags(
        converted.module,
        &operator,
        &ticket,
        &args.siem_format,
        args.siem_out.as_ref(),
        args.siem_udp.as_deref(),
    )?;
    if let Some(exp) = siem.as_mut() {
        exp.emit_many(&converted.alerts)?;
        exp.flush()?;
        writeln!(
            io::stderr(),
            "SIEM export: format={} emitted={}",
            exp.format().as_str(),
            exp.emitted()
        )?;
    }

    writeln!(
        io::stderr(),
        "import complete: lines={} alerts={} skipped={} errors={} truncated={} (audited -> {})",
        converted.lines_read,
        converted.alerts_kept,
        converted.skipped,
        converted.parse_errors,
        converted.truncated,
        audit.path().display()
    )?;

    if args.verbose > 0 {
        for a in converted.alerts.iter().take(20) {
            println!("[{}] {} src={} — {}", a.severity, a.rule, a.src, a.detail);
        }
        if converted.alerts.len() > 20 {
            writeln!(
                io::stderr(),
                "... {} more alerts (see --json-out)",
                converted.alerts.len() - 20
            )?;
        }
    }

    audit.info(
        converted.module,
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "lines_read": converted.lines_read,
            "alerts": converted.alerts_kept,
            "skipped": converted.skipped,
            "parse_errors": converted.parse_errors,
            "truncated": converted.truncated,
        }),
        "ok",
    )?;

    Ok(())
}

fn convert_eve(args: &ImportArgs, path: &Path) -> Result<Converted> {
    let event_types: Vec<String> = args
        .event_types
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let opts = EveImportOpts {
        event_types: event_types.clone(),
        max_alerts: args.max_alerts,
    };
    let result = import_eve_file(path, &opts)?;
    Ok(Converted {
        module: "import/suricata_eve",
        source: path.to_path_buf(),
        alerts: result.alerts,
        lines_read: result.lines_read,
        alerts_kept: result.alerts_kept,
        skipped: result.skipped,
        parse_errors: result.parse_errors,
        truncated: result.truncated,
        eve: Some(EveStats {
            lines_read: result.lines_read,
            alerts_kept: result.alerts_kept,
            skipped: result.skipped,
            parse_errors: result.parse_errors,
            truncated: result.truncated,
            event_types,
        }),
        zeek: None,
    })
}

fn convert_zeek(args: &ImportArgs, path: &Path, kind: ZeekLogKind) -> Result<Converted> {
    let note_types: Vec<String> = args
        .note_types
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let weird_names: Vec<String> = args
        .weird_names
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let name_filter = match kind {
        ZeekLogKind::Notice => note_types.clone(),
        ZeekLogKind::Weird => weird_names.clone(),
    };
    let opts = ZeekImportOpts {
        kind,
        name_filter,
        max_alerts: args.max_alerts,
    };
    let result = import_zeek_file(path, &opts)?;
    Ok(Converted {
        module: kind.module_name(),
        source: path.to_path_buf(),
        alerts: result.alerts,
        lines_read: result.lines_read,
        alerts_kept: result.alerts_kept,
        skipped: result.skipped,
        parse_errors: result.parse_errors,
        truncated: result.truncated,
        eve: None,
        zeek: Some(ZeekStats {
            kind: kind.as_str().into(),
            lines_read: result.lines_read,
            alerts_kept: result.alerts_kept,
            skipped: result.skipped,
            parse_errors: result.parse_errors,
            truncated: result.truncated,
            format: result.format,
            note_types: if kind == ZeekLogKind::Notice {
                note_types
            } else {
                Vec::new()
            },
            weird_names: if kind == ZeekLogKind::Weird {
                weird_names
            } else {
                Vec::new()
            },
        }),
    })
}
