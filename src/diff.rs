//! Compare two detect-compatible alert JSON reports.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::detect::Alert;

/// How to fingerprint an alert for set membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiffKeyMode {
    /// `rule|src|detail` (exact, ignoring timestamp).
    #[default]
    Full,
    /// `rule|src` only (ignore detail text drift).
    RuleSrc,
    /// `rule` only (aggregate by signature).
    Rule,
}

impl DiffKeyMode {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "full" | "exact" | "" => Ok(Self::Full),
            "rule-src" | "rule_src" | "src" => Ok(Self::RuleSrc),
            "rule" => Ok(Self::Rule),
            other => anyhow::bail!("unknown --key mode '{other}' (full|rule-src|rule)"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::RuleSrc => "rule-src",
            Self::Rule => "rule",
        }
    }
}

#[derive(Debug, Deserialize)]
struct DetectJson {
    #[serde(default)]
    alerts: Vec<Alert>,
}

/// One side of a multiset entry (representative alert + count).
#[derive(Debug, Clone, Serialize)]
pub struct DiffBucket {
    pub key: String,
    pub count: u64,
    pub sample: Alert,
}

/// Result of comparing before vs after alert sets.
#[derive(Debug, Clone, Serialize)]
pub struct AlertDiff {
    pub key_mode: String,
    pub before_total: u64,
    pub after_total: u64,
    pub unchanged: u64,
    pub only_before: Vec<DiffBucket>,
    pub only_after: Vec<DiffBucket>,
}

/// Load alerts from a detect / import / watch JSON report (`{ "alerts": [...] }`).
pub fn load_alerts(path: &Path) -> Result<Vec<Alert>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    // Accept either a full report object or a bare alert array.
    if let Ok(list) = serde_json::from_str::<Vec<Alert>>(&raw) {
        return Ok(list);
    }
    let report: DetectJson = serde_json::from_str(&raw)
        .with_context(|| format!("invalid detect JSON {}", path.display()))?;
    Ok(report.alerts)
}

fn fingerprint(alert: &Alert, mode: DiffKeyMode) -> String {
    match mode {
        DiffKeyMode::Full => format!("{}|{}|{}", alert.rule, alert.src, alert.detail),
        DiffKeyMode::RuleSrc => format!("{}|{}", alert.rule, alert.src),
        DiffKeyMode::Rule => alert.rule.clone(),
    }
}

fn to_multiset(alerts: &[Alert], mode: DiffKeyMode) -> HashMap<String, DiffBucket> {
    let mut map: HashMap<String, DiffBucket> = HashMap::new();
    for a in alerts {
        let key = fingerprint(a, mode);
        map.entry(key.clone())
            .and_modify(|b| b.count += 1)
            .or_insert(DiffBucket {
                key,
                count: 1,
                sample: a.clone(),
            });
    }
    map
}

/// Diff two alert lists using multiset counts per fingerprint.
pub fn diff_alerts(before: &[Alert], after: &[Alert], mode: DiffKeyMode) -> AlertDiff {
    let left = to_multiset(before, mode);
    let right = to_multiset(after, mode);

    let mut only_before = Vec::new();
    let mut only_after = Vec::new();
    let mut unchanged = 0u64;

    let mut keys: Vec<String> = left.keys().chain(right.keys()).cloned().collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        let lc = left.get(&key).map(|b| b.count).unwrap_or(0);
        let rc = right.get(&key).map(|b| b.count).unwrap_or(0);
        let shared = lc.min(rc);
        unchanged += shared;
        if lc > rc {
            let sample = left.get(&key).unwrap().sample.clone();
            only_before.push(DiffBucket {
                key: key.clone(),
                count: lc - rc,
                sample,
            });
        }
        if rc > lc {
            let sample = right.get(&key).unwrap().sample.clone();
            only_after.push(DiffBucket {
                key: key.clone(),
                count: rc - lc,
                sample,
            });
        }
    }

    only_before.sort_by(|a, b| a.key.cmp(&b.key));
    only_after.sort_by(|a, b| a.key.cmp(&b.key));

    AlertDiff {
        key_mode: mode.as_str().into(),
        before_total: before.len() as u64,
        after_total: after.len() as u64,
        unchanged,
        only_before,
        only_after,
    }
}

/// Human-readable summary for stdout/stderr.
pub fn format_diff_text(diff: &AlertDiff, verbose: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "alert diff (key={}): before={} after={} unchanged_keys={} gone={} new={}\n",
        diff.key_mode,
        diff.before_total,
        diff.after_total,
        diff.unchanged,
        diff.only_before.iter().map(|b| b.count).sum::<u64>(),
        diff.only_after.iter().map(|b| b.count).sum::<u64>(),
    ));
    if !diff.only_before.is_empty() {
        out.push_str("only in before (gone):\n");
        for b in &diff.only_before {
            out.push_str(&format!(
                "  - x{} [{}] {} src={} — {}\n",
                b.count, b.sample.severity, b.sample.rule, b.sample.src, b.sample.detail
            ));
        }
    }
    if !diff.only_after.is_empty() {
        out.push_str("only in after (new):\n");
        for b in &diff.only_after {
            out.push_str(&format!(
                "  - x{} [{}] {} src={} — {}\n",
                b.count, b.sample.severity, b.sample.rule, b.sample.src, b.sample.detail
            ));
        }
    }
    if verbose && diff.only_before.is_empty() && diff.only_after.is_empty() {
        out.push_str("(no differences)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(rule: &str, src: &str, detail: &str) -> Alert {
        Alert {
            ts_unix_ms: 1,
            rule: rule.into(),
            severity: "medium".into(),
            src: src.into(),
            detail: detail.into(),
        }
    }

    #[test]
    fn detects_new_and_gone() {
        let before = vec![
            alert("rare_port", "1.1.1.1", "4444"),
            alert("tcp_syn_scan", "2.2.2.2", "ports=20"),
        ];
        let after = vec![
            alert("rare_port", "1.1.1.1", "4444"),
            alert("dns_nxdomain_burst", "3.3.3.3", "n=12"),
        ];
        let d = diff_alerts(&before, &after, DiffKeyMode::Full);
        assert_eq!(d.unchanged, 1);
        assert_eq!(d.only_before.len(), 1);
        assert_eq!(d.only_before[0].sample.rule, "tcp_syn_scan");
        assert_eq!(d.only_after.len(), 1);
        assert_eq!(d.only_after[0].sample.rule, "dns_nxdomain_burst");
    }

    #[test]
    fn rule_src_ignores_detail() {
        let before = vec![alert("rare_port", "1.1.1.1", "old")];
        let after = vec![alert("rare_port", "1.1.1.1", "new")];
        let full = diff_alerts(&before, &after, DiffKeyMode::Full);
        assert_eq!(full.unchanged, 0);
        let loose = diff_alerts(&before, &after, DiffKeyMode::RuleSrc);
        assert_eq!(loose.unchanged, 1);
        assert!(loose.only_before.is_empty());
        assert!(loose.only_after.is_empty());
    }

    #[test]
    fn multiset_counts_duplicates() {
        let before = vec![alert("r", "a", "d"), alert("r", "a", "d")];
        let after = vec![alert("r", "a", "d")];
        let d = diff_alerts(&before, &after, DiffKeyMode::Full);
        assert_eq!(d.unchanged, 1);
        assert_eq!(d.only_before[0].count, 1);
    }
}
