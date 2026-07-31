//! Zeek `notice.log` / `weird.log` import (TSV or JSONL) → Devil Eye alerts.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::detect::Alert;

const MAX_ALERTS_DEFAULT: usize = 100_000;

/// Which Zeek log flavor to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZeekLogKind {
    #[default]
    Notice,
    Weird,
}

impl ZeekLogKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Weird => "weird",
        }
    }

    pub fn module_name(self) -> &'static str {
        match self {
            Self::Notice => "import/zeek_notice",
            Self::Weird => "import/zeek_weird",
        }
    }
}

/// Options for importing a Zeek log.
#[derive(Debug, Clone)]
pub struct ZeekImportOpts {
    pub kind: ZeekLogKind,
    /// Keep only these type names (empty = all).
    /// Notice: `note` field. Weird: `name` field. Case-insensitive.
    pub name_filter: Vec<String>,
    /// Hard cap on converted alerts (memory bound).
    pub max_alerts: usize,
}

impl Default for ZeekImportOpts {
    fn default() -> Self {
        Self {
            kind: ZeekLogKind::Notice,
            name_filter: Vec::new(),
            max_alerts: MAX_ALERTS_DEFAULT,
        }
    }
}

/// Result of a Zeek import pass.
#[derive(Debug, Clone)]
pub struct ZeekImportResult {
    pub alerts: Vec<Alert>,
    pub lines_read: u64,
    pub alerts_kept: u64,
    pub skipped: u64,
    pub parse_errors: u64,
    pub truncated: bool,
    pub format: String,
    pub kind: ZeekLogKind,
}

/// Read a Zeek `notice.log` (TSV with `#fields` or JSONL) and convert to alerts.
pub fn import_zeek_file(path: &Path, opts: &ZeekImportOpts) -> Result<ZeekImportResult> {
    let label = match opts.kind {
        ZeekLogKind::Notice => "notice.log",
        ZeekLogKind::Weird => "weird.log",
    };
    let file = File::open(path)
        .with_context(|| format!("failed to open Zeek {label} {}", path.display()))?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed reading {}", path.display()))?;

    if opts.max_alerts == 0 {
        bail!("--max-alerts must be greater than zero");
    }

    let allowed: Vec<String> = opts
        .name_filter
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let format = detect_format(&lines);
    match format.as_str() {
        "jsonl" => import_jsonl(&lines, &allowed, opts.max_alerts, format, opts.kind),
        "tsv" => import_tsv(&lines, &allowed, opts.max_alerts, format, opts.kind),
        other => bail!("unsupported Zeek {label} format: {other}"),
    }
}

fn detect_format(lines: &[String]) -> String {
    for line in lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('{') {
            return "jsonl".into();
        }
        return "tsv".into();
    }
    "tsv".into()
}

fn import_jsonl(
    lines: &[String],
    allowed: &[String],
    max_alerts: usize,
    format: String,
    kind: ZeekLogKind,
) -> Result<ZeekImportResult> {
    let mut alerts = Vec::new();
    let mut lines_read = 0u64;
    let mut skipped = 0u64;
    let mut parse_errors = 0u64;
    let mut truncated = false;

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines_read += 1;
        match convert_zeek_json(trimmed, allowed, kind) {
            Ok(Some(alert)) => {
                if alerts.len() >= max_alerts {
                    truncated = true;
                    break;
                }
                alerts.push(alert);
            }
            Ok(None) => skipped += 1,
            Err(_) => parse_errors += 1,
        }
    }

    Ok(ZeekImportResult {
        alerts_kept: alerts.len() as u64,
        alerts,
        lines_read,
        skipped,
        parse_errors,
        truncated,
        format,
        kind,
    })
}

fn import_tsv(
    lines: &[String],
    allowed: &[String],
    max_alerts: usize,
    format: String,
    kind: ZeekLogKind,
) -> Result<ZeekImportResult> {
    let mut fields: Vec<String> = Vec::new();
    let mut unset = "-".to_string();
    let mut alerts = Vec::new();
    let mut lines_read = 0u64;
    let mut skipped = 0u64;
    let mut parse_errors = 0u64;
    let mut truncated = false;

    for line in lines {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            if let Some(v) = rest
                .strip_prefix("fields\t")
                .or_else(|| rest.strip_prefix("fields "))
            {
                fields = v
                    .split('\t')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            } else if let Some(v) = rest
                .strip_prefix("unset_field\t")
                .or_else(|| rest.strip_prefix("unset_field "))
            {
                unset = v.to_string();
            }
            continue;
        }

        lines_read += 1;
        if fields.is_empty() {
            parse_errors += 1;
            continue;
        }

        let cols: Vec<&str> = trimmed.split('\t').collect();
        let mut map: HashMap<String, String> = HashMap::new();
        for (i, name) in fields.iter().enumerate() {
            let raw = cols.get(i).copied().unwrap_or("");
            if raw == unset {
                continue;
            }
            map.insert(name.clone(), raw.to_string());
        }

        match alert_from_zeek_map(&map, allowed, kind) {
            Ok(Some(alert)) => {
                if alerts.len() >= max_alerts {
                    truncated = true;
                    break;
                }
                alerts.push(alert);
            }
            Ok(None) => skipped += 1,
            Err(_) => parse_errors += 1,
        }
    }

    Ok(ZeekImportResult {
        alerts_kept: alerts.len() as u64,
        alerts,
        lines_read,
        skipped,
        parse_errors,
        truncated,
        format,
        kind,
    })
}

/// Convert one Zeek JSON object line into an alert when it matches filters.
pub fn convert_zeek_json(
    line: &str,
    allowed: &[String],
    kind: ZeekLogKind,
) -> Result<Option<Alert>> {
    let v: Value = serde_json::from_str(line).context("invalid Zeek JSON line")?;
    let mut map = HashMap::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            let s = match val {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Null => continue,
                other => other.to_string(),
            };
            map.insert(k.clone(), s);
        }
    } else {
        bail!("Zeek JSON line must be an object");
    }
    alert_from_zeek_map(&map, allowed, kind)
}

/// Back-compat wrapper for notice JSON lines.
pub fn convert_notice_json(line: &str, allowed_notes: &[String]) -> Result<Option<Alert>> {
    convert_zeek_json(line, allowed_notes, ZeekLogKind::Notice)
}

fn alert_from_zeek_map(
    map: &HashMap<String, String>,
    allowed: &[String],
    kind: ZeekLogKind,
) -> Result<Option<Alert>> {
    match kind {
        ZeekLogKind::Notice => alert_from_notice_map(map, allowed),
        ZeekLogKind::Weird => alert_from_weird_map(map, allowed),
    }
}

fn alert_from_notice_map(
    map: &HashMap<String, String>,
    allowed_notes: &[String],
) -> Result<Option<Alert>> {
    let note = map
        .get("note")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Notice::Unknown".into());

    if !allowed_notes.is_empty() {
        let note_lc = note.to_ascii_lowercase();
        if !allowed_notes.iter().any(|n| n == &note_lc) {
            return Ok(None);
        }
    }

    let src = first_nonempty(map, &["src", "id.orig_h"]).unwrap_or_else(|| "unknown".into());
    let dst = first_nonempty(map, &["dst", "id.resp_h"]).unwrap_or_else(|| "-".into());
    let sport = first_nonempty(map, &["id.orig_p"]);
    let dport = first_nonempty(map, &["p", "id.resp_p"]);
    let proto = map
        .get("proto")
        .map(|s| s.as_str())
        .unwrap_or("-")
        .to_string();
    let msg = map
        .get("msg")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Zeek notice");
    let sub = map.get("sub").map(|s| s.as_str()).unwrap_or("-");
    let n = map.get("n").map(|s| s.as_str()).unwrap_or("-");

    let detail = truncate_detail(format!(
        "{msg} | note={note} {proto} {src}{} -> {dst}{} sub={sub} n={n}",
        sport.as_ref().map(|p| format!(":{p}")).unwrap_or_default(),
        dport.as_ref().map(|p| format!(":{p}")).unwrap_or_default(),
    ));

    let ts_raw = map.get("ts").map(|s| s.as_str()).unwrap_or("");
    Ok(Some(Alert {
        ts_unix_ms: parse_zeek_timestamp(ts_raw).unwrap_or(0),
        rule: format!("zeek:notice:{note}"),
        severity: map_zeek_severity(&note),
        src,
        detail,
    }))
}

fn alert_from_weird_map(
    map: &HashMap<String, String>,
    allowed_names: &[String],
) -> Result<Option<Alert>> {
    let name = map
        .get("name")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown_weird".into());

    if !allowed_names.is_empty() {
        let name_lc = name.to_ascii_lowercase();
        if !allowed_names.iter().any(|n| n == &name_lc) {
            return Ok(None);
        }
    }

    let src = first_nonempty(map, &["id.orig_h", "src"]).unwrap_or_else(|| "unknown".into());
    let dst = first_nonempty(map, &["id.resp_h", "dst"]).unwrap_or_else(|| "-".into());
    let sport = first_nonempty(map, &["id.orig_p"]);
    let dport = first_nonempty(map, &["id.resp_p"]);
    let addl = map.get("addl").map(|s| s.as_str()).unwrap_or("-");
    let source = map.get("source").map(|s| s.as_str()).unwrap_or("-");
    let notice = map.get("notice").map(|s| s.as_str()).unwrap_or("F");

    let detail = truncate_detail(format!(
        "weird name={name} {src}{} -> {dst}{} addl={addl} source={source} notice={notice}",
        sport.as_ref().map(|p| format!(":{p}")).unwrap_or_default(),
        dport.as_ref().map(|p| format!(":{p}")).unwrap_or_default(),
    ));

    let ts_raw = map.get("ts").map(|s| s.as_str()).unwrap_or("");
    Ok(Some(Alert {
        ts_unix_ms: parse_zeek_timestamp(ts_raw).unwrap_or(0),
        rule: format!("zeek:weird:{name}"),
        severity: map_weird_severity(&name),
        src,
        detail,
    }))
}

fn first_nonempty(map: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = map.get(*k) {
            let t = v.trim();
            if !t.is_empty() && t != "-" {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Heuristic severity from Zeek `note` enum name.
pub fn map_zeek_severity(note: &str) -> String {
    let n = note.to_ascii_lowercase();
    if n.contains("password")
        || n.contains("bruteforc")
        || n.contains("port_scan")
        || n.contains("address_scan")
        || n.contains("scan::")
        || n.contains("attack")
        || n.contains("exploit")
        || n.contains("trw::")
    {
        "high".into()
    } else if n.contains("nxdomain")
        || n.contains("weird")
        || n.contains("sensitive")
        || n.contains("content_gap")
    {
        "low".into()
    } else {
        "medium".into()
    }
}

/// Heuristic severity for weird event names (mostly low / medium).
pub fn map_weird_severity(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    if n.contains("overflow")
        || n.contains("underflow")
        || n.contains("bad_icmp")
        || n.contains("truncated_header")
        || n.contains("possible_split_routing")
        || n.contains("active_http_proxy")
    {
        "medium".into()
    } else {
        "low".into()
    }
}

/// Parse Zeek epoch time (`1695016221.532140`) to unix milliseconds.
pub fn parse_zeek_timestamp(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() || s == "-" {
        return None;
    }
    let f: f64 = s.parse().ok()?;
    if !f.is_finite() || f < 0.0 {
        return None;
    }
    let secs = f.trunc() as u64;
    let millis = ((f.fract() * 1000.0).round() as u64).min(999);
    Some(secs.saturating_mul(1000).saturating_add(millis))
}

fn truncate_detail(mut s: String) -> String {
    const MAX: usize = 400;
    if s.len() > MAX {
        s.truncate(MAX);
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_epoch_ts() {
        let ms = parse_zeek_timestamp("1695016221.532140").unwrap();
        assert_eq!(ms / 1000, 1_695_016_221);
        assert_eq!(ms % 1000, 532);
    }

    #[test]
    fn converts_json_notice() {
        let line = r#"{"ts":1695016221.532140,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"10.0.0.50","id.orig_p":54321,"id.resp_h":"10.0.0.1","id.resp_p":22,"proto":"tcp","note":"SSH::Password_Guessing","msg":"10.0.0.50 appears to be guessing SSH passwords","sub":"Sampled servers: 10.0.0.1/22","src":"10.0.0.50","dst":"10.0.0.1","p":22,"n":30}"#;
        let alert = convert_notice_json(line, &[]).unwrap().unwrap();
        assert_eq!(alert.rule, "zeek:notice:SSH::Password_Guessing");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.src, "10.0.0.50");
        assert!(alert.detail.contains("guessing SSH"));
        assert!(alert.detail.contains(":22"));
    }

    #[test]
    fn filters_note_types() {
        let line = r#"{"ts":1.0,"note":"DNS::NXDomain","msg":"nx","src":"1.1.1.1"}"#;
        assert!(
            convert_notice_json(line, &["ssh::password_guessing".into()])
                .unwrap()
                .is_none()
        );
        let kept = convert_notice_json(line, &["dns::nxdomain".into()])
            .unwrap()
            .unwrap();
        assert_eq!(kept.severity, "low");
    }

    #[test]
    fn maps_severity_heuristics() {
        assert_eq!(map_zeek_severity("Scan::Port_Scan"), "high");
        assert_eq!(map_zeek_severity("DNS::NXDomain"), "low");
        assert_eq!(map_zeek_severity("SSL::Invalid_Server_Cert"), "medium");
    }

    #[test]
    fn converts_json_weird() {
        let line = r#"{"ts":1695016400.1,"uid":"Cweird1","id.orig_h":"10.0.0.9","id.orig_p":40122,"id.resp_h":"10.0.0.5","id.resp_p":80,"name":"above_hole_data_without_any_acks","addl":"-","notice":false,"source":"TCP"}"#;
        let alert = convert_zeek_json(line, &[], ZeekLogKind::Weird)
            .unwrap()
            .unwrap();
        assert_eq!(alert.rule, "zeek:weird:above_hole_data_without_any_acks");
        assert_eq!(alert.severity, "low");
        assert_eq!(alert.src, "10.0.0.9");
        assert!(alert.detail.contains("source=TCP"));
    }

    #[test]
    fn filters_weird_names() {
        let line = r#"{"ts":1.0,"name":"dns_unmatched_msg","id.orig_h":"1.1.1.1"}"#;
        assert!(
            convert_zeek_json(line, &["bad_tcp_checksum".into()], ZeekLogKind::Weird)
                .unwrap()
                .is_none()
        );
        let kept = convert_zeek_json(line, &["dns_unmatched_msg".into()], ZeekLogKind::Weird)
            .unwrap()
            .unwrap();
        assert_eq!(kept.rule, "zeek:weird:dns_unmatched_msg");
    }

    #[test]
    fn imports_tsv_sample_shape() {
        let tsv = "\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tnote\tmsg\tsub\tsrc\tdst\tp\tn
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tenum\tstring\tstring\taddr\taddr\tport\tcount
1695016221.532140\tC1\t10.0.0.50\t54321\t10.0.0.1\t22\ttcp\tSSH::Password_Guessing\tguessing passwords\tsampled\t10.0.0.50\t10.0.0.1\t22\t30
1695016300.100000\tC2\t192.168.1.20\t45000\t8.8.8.8\t53\tudp\tDNS::NXDomain\tnxdomain query\tevil.example\t192.168.1.20\t8.8.8.8\t53\t-
";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notice.log");
        std::fs::write(&path, tsv).unwrap();
        let result = import_zeek_file(&path, &ZeekImportOpts::default()).unwrap();
        assert_eq!(result.format, "tsv");
        assert_eq!(result.alerts_kept, 2);
        assert_eq!(result.alerts[0].rule, "zeek:notice:SSH::Password_Guessing");
        assert_eq!(result.alerts[1].severity, "low");
    }

    #[test]
    fn imports_weird_tsv() {
        let tsv = "\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tname\taddl\tnotice\tsource
#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tbool\tstring
1695016400.100000\tCw1\t10.0.0.9\t40122\t10.0.0.5\t80\tabove_hole_data_without_any_acks\t-\tF\tTCP
1695016401.000000\tCw2\t10.0.0.9\t40123\t10.0.0.5\t443\tbad_TCP_checksum\t-\tF\tTCP
";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weird.log");
        std::fs::write(&path, tsv).unwrap();
        let opts = ZeekImportOpts {
            kind: ZeekLogKind::Weird,
            ..Default::default()
        };
        let result = import_zeek_file(&path, &opts).unwrap();
        assert_eq!(result.kind, ZeekLogKind::Weird);
        assert_eq!(result.alerts_kept, 2);
        assert!(result.alerts[0].rule.starts_with("zeek:weird:"));
        assert_eq!(result.alerts[1].severity, "low");
    }
}
