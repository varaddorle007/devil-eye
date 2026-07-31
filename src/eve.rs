//! Suricata EVE JSONL import → Devil Eye alerts.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::detect::Alert;

const MAX_ALERTS_DEFAULT: usize = 100_000;

/// Options for importing an EVE log.
#[derive(Debug, Clone)]
pub struct EveImportOpts {
    /// Only keep these `event_type` values (default: `alert`).
    pub event_types: Vec<String>,
    /// Hard cap on converted alerts (memory bound).
    pub max_alerts: usize,
}

impl Default for EveImportOpts {
    fn default() -> Self {
        Self {
            event_types: vec!["alert".into()],
            max_alerts: MAX_ALERTS_DEFAULT,
        }
    }
}

/// Result of an EVE import pass.
#[derive(Debug, Clone)]
pub struct EveImportResult {
    pub alerts: Vec<Alert>,
    pub lines_read: u64,
    pub alerts_kept: u64,
    pub skipped: u64,
    pub parse_errors: u64,
    pub truncated: bool,
}

/// Read a Suricata `eve.json` (JSONL) file and convert matching events to alerts.
pub fn import_eve_file(path: &Path, opts: &EveImportOpts) -> Result<EveImportResult> {
    let file =
        File::open(path).with_context(|| format!("failed to open EVE file {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut alerts = Vec::new();
    let mut lines_read = 0u64;
    let mut skipped = 0u64;
    let mut parse_errors = 0u64;
    let mut truncated = false;

    let allowed: Vec<String> = opts
        .event_types
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if allowed.is_empty() {
        bail!("at least one --event-type is required");
    }
    if opts.max_alerts == 0 {
        bail!("--max-alerts must be greater than zero");
    }

    for line in reader.lines() {
        let line = line.with_context(|| format!("failed reading {}", path.display()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        lines_read += 1;

        match convert_eve_line(trimmed, &allowed) {
            Ok(Some(alert)) => {
                if alerts.len() >= opts.max_alerts {
                    truncated = true;
                    break;
                }
                alerts.push(alert);
            }
            Ok(None) => skipped += 1,
            Err(_) => parse_errors += 1,
        }
    }

    let alerts_kept = alerts.len() as u64;
    Ok(EveImportResult {
        alerts,
        lines_read,
        alerts_kept,
        skipped,
        parse_errors,
        truncated,
    })
}

/// Convert one EVE JSON object line into an alert when it matches filters.
pub fn convert_eve_line(line: &str, allowed_types: &[String]) -> Result<Option<Alert>> {
    let v: Value = serde_json::from_str(line).context("invalid EVE JSON line")?;
    let event_type = v
        .get("event_type")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !allowed_types.iter().any(|t| t == &event_type) {
        return Ok(None);
    }

    match event_type.as_str() {
        "alert" => Ok(Some(alert_from_eve(&v)?)),
        "anomaly" => Ok(Some(anomaly_from_eve(&v)?)),
        other => {
            // Generic fallback for explicitly requested event types.
            Ok(Some(generic_from_eve(&v, other)?))
        }
    }
}

#[derive(Debug, Deserialize)]
struct EveAlertBlock {
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    signature_id: Option<u64>,
    #[serde(default)]
    gid: Option<u64>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    severity: Option<u64>,
    #[serde(default)]
    action: Option<String>,
}

fn alert_from_eve(v: &Value) -> Result<Alert> {
    let block: EveAlertBlock = serde_json::from_value(
        v.get("alert")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("alert event missing alert object"))?,
    )?;

    let sid = block.signature_id.unwrap_or(0);
    let gid = block.gid.unwrap_or(1);
    let sig = block
        .signature
        .unwrap_or_else(|| format!("suricata signature {sid}"));
    let rule = format!("suricata:{gid}:{sid}");
    let severity = map_suricata_severity(block.severity);
    let src = v
        .get("src_ip")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let dst = v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("-");
    let sport = v.get("src_port").and_then(json_u64).map(|p| p.to_string());
    let dport = v.get("dest_port").and_then(json_u64).map(|p| p.to_string());
    let proto = v.get("proto").and_then(|x| x.as_str()).unwrap_or("-");
    let category = block.category.unwrap_or_else(|| "-".into());
    let action = block.action.unwrap_or_else(|| "-".into());
    let app = v.get("app_proto").and_then(|x| x.as_str()).unwrap_or("-");

    let detail = format!(
        "{sig} | cat={category} action={action} {proto} {src}{} -> {dst}{} app={app}",
        sport.map(|p| format!(":{p}")).unwrap_or_default(),
        dport.map(|p| format!(":{p}")).unwrap_or_default(),
    );

    Ok(Alert {
        ts_unix_ms: parse_eve_timestamp(v.get("timestamp").and_then(|x| x.as_str()).unwrap_or(""))
            .unwrap_or(0),
        rule,
        severity,
        src,
        detail: truncate_detail(detail),
    })
}

fn anomaly_from_eve(v: &Value) -> Result<Alert> {
    let anom = v.get("anomaly").cloned().unwrap_or(Value::Null);
    let atype = anom
        .get("type")
        .and_then(|x| x.as_str())
        .or_else(|| anom.get("event").and_then(|x| x.as_str()))
        .unwrap_or("anomaly");
    let src = v
        .get("src_ip")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let dst = v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("-");
    let proto = v.get("proto").and_then(|x| x.as_str()).unwrap_or("-");
    let detail = truncate_detail(format!(
        "Suricata anomaly type={atype} {proto} {src} -> {dst}"
    ));
    Ok(Alert {
        ts_unix_ms: parse_eve_timestamp(v.get("timestamp").and_then(|x| x.as_str()).unwrap_or(""))
            .unwrap_or(0),
        rule: format!("suricata:anomaly:{atype}"),
        severity: "low".into(),
        src,
        detail,
    })
}

fn generic_from_eve(v: &Value, event_type: &str) -> Result<Alert> {
    let src = v
        .get("src_ip")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    Ok(Alert {
        ts_unix_ms: parse_eve_timestamp(v.get("timestamp").and_then(|x| x.as_str()).unwrap_or(""))
            .unwrap_or(0),
        rule: format!("suricata:event:{event_type}"),
        severity: "info".into(),
        src,
        detail: truncate_detail(format!("Suricata event_type={event_type}")),
    })
}

fn json_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().map(|n| n as u64))
        .or_else(|| v.as_str()?.parse().ok())
}

/// Suricata alert.severity: 1 = high, 2 = medium, 3 = low.
fn map_suricata_severity(sev: Option<u64>) -> String {
    match sev.unwrap_or(2) {
        1 => "high".into(),
        2 => "medium".into(),
        3 => "low".into(),
        _ => "medium".into(),
    }
}

fn truncate_detail(mut s: String) -> String {
    const MAX: usize = 400;
    if s.len() > MAX {
        s.truncate(MAX);
        s.push('…');
    }
    s
}

/// Parse Suricata timestamps like `2017-04-07T22:24:37.251547+0100` or `…Z` / `…+00:00`.
pub fn parse_eve_timestamp(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let (datetime, offset_secs) = split_tz(s)?;
    let (date, time) = datetime
        .split_once('T')
        .or_else(|| datetime.split_once(' '))?;
    let mut date_parts = date.split('-');
    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;

    let (hms, frac) = match time.split_once('.') {
        Some((hms, frac)) => (hms, Some(frac)),
        None => (time, None),
    };
    let mut tparts = hms.split(':');
    let hour: u64 = tparts.next()?.parse().ok()?;
    let min: u64 = tparts.next()?.parse().ok()?;
    let sec: u64 = tparts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let millis = match frac {
        Some(f) => {
            let digits: String = f.chars().take(3).collect();
            let padded = format!("{digits:0<3}");
            padded.parse::<u64>().unwrap_or(0)
        }
        None => 0,
    };

    let days = days_from_civil(year, month, day)?;
    let day_secs = hour * 3600 + min * 60 + sec;
    let unix = (days * 86_400) + i64::try_from(day_secs).ok()? - offset_secs;
    if unix < 0 {
        return None;
    }
    Some((unix as u64).saturating_mul(1000).saturating_add(millis))
}

fn split_tz(s: &str) -> Option<(&str, i64)> {
    if let Some(rest) = s.strip_suffix('Z').or_else(|| s.strip_suffix('z')) {
        return Some((rest, 0));
    }
    // Find last + or - that starts a timezone (not the date separator).
    let bytes = s.as_bytes();
    let mut idx = None;
    for i in (1..bytes.len()).rev() {
        if bytes[i] == b'+' || bytes[i] == b'-' {
            // Timezone starts after the time portion (must contain ':').
            if s[..i].contains('T') || s[..i].contains(' ') {
                idx = Some(i);
                break;
            }
        }
    }
    let i = idx?;
    let (datetime, tz) = s.split_at(i);
    let offset = parse_offset(tz)?;
    Some((datetime, offset))
}

fn parse_offset(tz: &str) -> Option<i64> {
    let sign = match tz.chars().next()? {
        '+' => 1i64,
        '-' => -1,
        _ => return None,
    };
    let body = &tz[1..];
    let (hh, mm) = if let Some((h, m)) = body.split_once(':') {
        (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
    } else if body.len() == 4 {
        (
            body[..2].parse::<i64>().ok()?,
            body[2..].parse::<i64>().ok()?,
        )
    } else if body.len() == 2 {
        (body.parse::<i64>().ok()?, 0)
    } else {
        return None;
    };
    Some(sign * (hh * 3600 + mm * 60))
}

/// Days since Unix epoch for a Gregorian date (Howard Hinnant).
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    y -= i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suricata_timestamp_zulu() {
        let ms = parse_eve_timestamp("2023-09-18T06:13:41.532140+0000").unwrap();
        assert_eq!(ms / 1000, 1_695_017_621);
        assert_eq!(ms % 1000, 532);
    }

    #[test]
    fn parses_offset_colon() {
        let a = parse_eve_timestamp("2023-09-18T06:13:41.000+00:00").unwrap();
        let b = parse_eve_timestamp("2023-09-18T06:13:41.000Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn converts_alert_line() {
        let line = r#"{"timestamp":"2017-04-07T21:24:37.251547+0000","event_type":"alert","src_ip":"192.168.2.14","src_port":50096,"dest_ip":"209.53.113.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2018358,"rev":10,"signature":"ET HUNTING GENERIC SUSPICIOUS POST","category":"Potentially Bad Traffic","severity":2},"app_proto":"http"}"#;
        let alert = convert_eve_line(line, &["alert".into()]).unwrap().unwrap();
        assert_eq!(alert.rule, "suricata:1:2018358");
        assert_eq!(alert.severity, "medium");
        assert_eq!(alert.src, "192.168.2.14");
        assert!(alert.detail.contains("ET HUNTING"));
        assert!(alert.detail.contains(":80"));
    }

    #[test]
    fn skips_non_alert() {
        let line = r#"{"timestamp":"2017-04-07T21:24:37.251547+0000","event_type":"dns","src_ip":"1.1.1.1"}"#;
        assert!(convert_eve_line(line, &["alert".into()]).unwrap().is_none());
    }

    #[test]
    fn maps_high_severity() {
        assert_eq!(map_suricata_severity(Some(1)), "high");
        assert_eq!(map_suricata_severity(Some(3)), "low");
    }
}
