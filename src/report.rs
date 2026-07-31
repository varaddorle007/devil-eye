//! Engagement evidence report assembly (Markdown + HTML).

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::scope::Scope;

/// Built-in evidence pack layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportTemplate {
    /// Full technical pack (timeline, raw JSON, audit).
    #[default]
    Full,
    /// Management-oriented findings summary (no raw dumps).
    Executive,
    /// One-page KPI + highlights.
    Compact,
}

impl ReportTemplate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Executive => "executive",
            Self::Compact => "compact",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "full" | "technical" => Ok(Self::Full),
            "executive" | "exec" => Ok(Self::Executive),
            "compact" | "short" => Ok(Self::Compact),
            other => {
                anyhow::bail!("unknown report template '{other}' (expected full|executive|compact)")
            }
        }
    }
}

/// Assembled engagement evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementReport {
    pub title: String,
    pub generated_unix_ms: u64,
    pub ticket_id: String,
    pub operator: String,
    pub organization: String,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub scan: Option<Value>,
    pub enumeration: Option<Value>,
    pub detection: Option<Value>,
    pub audit_events: Vec<Value>,
    pub pcap_summary: Option<PcapSummary>,
    pub notes: Vec<String>,
    /// Merged chronological engagement timeline (audit + alerts + milestones).
    pub timeline: Vec<TimelineEvent>,
}

/// One point on the engagement timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEvent {
    pub ts_unix_ms: u64,
    /// `audit` | `alert` | `scan` | `enum` | `capture` | `note` | `system`
    pub kind: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapSummary {
    pub path: String,
    pub packets: u64,
    pub decode_ok: u64,
    pub decode_fail: u64,
    pub tcp: u64,
    pub udp: u64,
    pub dns: u64,
    pub http: u64,
    pub ssh: u64,
    pub tls: u64,
    pub arp: u64,
    pub dhcp: u64,
    pub first_ts_unix_ms: Option<u64>,
    pub last_ts_unix_ms: Option<u64>,
    /// Fixed-width packet activity buckets across the capture window.
    pub timeline_buckets: Vec<PcapTimelineBucket>,
}

/// One time-bucket of PCAP activity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapTimelineBucket {
    pub ts_unix_ms: u64,
    pub packets: u64,
    pub tcp: u64,
    pub udp: u64,
    pub app: u64,
}

impl PcapSummary {
    /// Duration of the capture window in milliseconds, if known.
    pub fn duration_ms(&self) -> Option<u64> {
        match (self.first_ts_unix_ms, self.last_ts_unix_ms) {
            (Some(a), Some(b)) if b >= a => Some(b - a),
            _ => None,
        }
    }

    /// Bucket with the highest packet count (traffic peak).
    pub fn peak_bucket(&self) -> Option<&PcapTimelineBucket> {
        self.timeline_buckets.iter().max_by_key(|b| b.packets)
    }
}

/// Inputs used to build a report.
#[derive(Debug, Default)]
pub struct ReportInputs {
    pub scope: Option<Scope>,
    pub scan_json: Option<Value>,
    pub enum_json: Option<Value>,
    pub detect_json: Option<Value>,
    pub audit_events: Vec<Value>,
    pub pcap_summary: Option<PcapSummary>,
    pub notes: Vec<String>,
}

impl EngagementReport {
    pub fn assemble(inputs: ReportInputs) -> Self {
        let (ticket_id, operator, organization, targets, ports) = if let Some(s) = &inputs.scope {
            (
                s.ticket_id.clone(),
                s.operator.clone(),
                s.organization.clone(),
                s.targets.clone(),
                s.ports.clone(),
            )
        } else {
            (
                "unscoped".into(),
                "anonymous".into(),
                String::new(),
                Vec::new(),
                Vec::new(),
            )
        };

        let generated_unix_ms = now_ms();
        let timeline = build_timeline(
            generated_unix_ms,
            &inputs.audit_events,
            &inputs.scan_json,
            &inputs.enum_json,
            &inputs.detect_json,
            &inputs.pcap_summary,
            &inputs.notes,
        );

        Self {
            title: format!("Devil Eye Engagement Report - {ticket_id}"),
            generated_unix_ms,
            ticket_id,
            operator,
            organization,
            targets,
            ports,
            scan: inputs.scan_json,
            enumeration: inputs.enum_json,
            detection: inputs.detect_json,
            audit_events: inputs.audit_events,
            pcap_summary: inputs.pcap_summary,
            notes: inputs.notes,
            timeline,
        }
    }

    pub fn to_markdown(&self) -> String {
        self.to_markdown_template(ReportTemplate::Full)
    }

    pub fn to_markdown_template(&self, template: ReportTemplate) -> String {
        match template {
            ReportTemplate::Full => self.render_markdown_full(true),
            ReportTemplate::Executive => self.render_markdown_executive(),
            ReportTemplate::Compact => self.render_markdown_compact(),
        }
    }

    pub fn to_html(&self) -> String {
        self.to_html_template(ReportTemplate::Full)
    }

    pub fn to_html_template(&self, template: ReportTemplate) -> String {
        let kpis = collect_kpis(self);
        let charts = match template {
            ReportTemplate::Compact => String::new(),
            _ => html_charts(self),
        };
        let timeline = match template {
            ReportTemplate::Full => html_timeline(self),
            ReportTemplate::Executive => html_timeline_limited(self, 8),
            ReportTemplate::Compact => String::new(),
        };
        let details = match template {
            ReportTemplate::Full => markdownish_to_html(&self.render_markdown_full(false)),
            ReportTemplate::Executive => {
                markdownish_to_html(&self.render_markdown_executive_body())
            }
            ReportTemplate::Compact => markdownish_to_html(&self.render_markdown_compact()),
        };
        let subtitle = match template {
            ReportTemplate::Full => "Authorized engagement evidence pack",
            ReportTemplate::Executive => "Executive findings summary",
            ReportTemplate::Compact => "Compact engagement snapshot",
        };

        self.wrap_html(
            template.as_str(),
            subtitle,
            &kpis,
            &charts,
            &timeline,
            &details,
        )
    }

    fn render_markdown_full(&self, include_timeline: bool) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!(
            "- **Template:** full\n- **Generated (unix ms):** {}\n- **Ticket:** {}\n- **Operator:** {}\n- **Organization:** {}\n\n",
            self.generated_unix_ms, self.ticket_id, self.operator, self.organization
        ));

        md.push_str("## Scope\n\n");
        if self.targets.is_empty() {
            md.push_str("_No scope file provided._\n\n");
        } else {
            md.push_str(&format!("- **Targets:** {}\n", self.targets.join(", ")));
            md.push_str(&format!(
                "- **Ports:** {}\n\n",
                self.ports
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if include_timeline && !self.timeline.is_empty() {
            md.push_str("## Timeline\n\n");
            md.push_str("| ts_unix_ms | kind | title | detail |\n");
            md.push_str("|---|---|---|---|\n");
            for ev in &self.timeline {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    ev.ts_unix_ms,
                    esc_cell(&ev.kind),
                    esc_cell(&ev.title),
                    esc_cell(&ev.detail)
                ));
            }
            md.push('\n');
        }

        if let Some(pcap) = &self.pcap_summary {
            md.push_str("## Capture summary\n\n");
            md.push_str(&format!("- **PCAP:** `{}`\n", pcap.path));
            md.push_str(&format!("- **Packets:** {}\n", pcap.packets));
            md.push_str(&format!(
                "- **Decode OK / fail:** {} / {}\n",
                pcap.decode_ok, pcap.decode_fail
            ));
            if let (Some(first), Some(last)) = (pcap.first_ts_unix_ms, pcap.last_ts_unix_ms) {
                md.push_str(&format!("- **Time range (unix ms):** {first} → {last}"));
                if let Some(dur) = pcap.duration_ms() {
                    md.push_str(&format!(" ({dur} ms)\n"));
                } else {
                    md.push('\n');
                }
            }
            md.push_str(&format!(
                "- **TCP / UDP / DNS / HTTP / SSH / TLS / ARP / DHCP:** {} / {} / {} / {} / {} / {} / {} / {}\n",
                pcap.tcp, pcap.udp, pcap.dns, pcap.http, pcap.ssh, pcap.tls, pcap.arp, pcap.dhcp
            ));
            if !pcap.timeline_buckets.is_empty() {
                md.push_str("\n### Packet timeline\n\n");
                md.push_str("| bucket_start_ms | packets | tcp | udp | app |\n");
                md.push_str("|---|---|---|---|---|\n");
                for b in &pcap.timeline_buckets {
                    md.push_str(&format!(
                        "| {} | {} | {} | {} | {} |\n",
                        b.ts_unix_ms, b.packets, b.tcp, b.udp, b.app
                    ));
                }
                if let Some(peak) = pcap.peak_bucket() {
                    md.push_str(&format!(
                        "\n- **Peak bucket:** {} packets @ {} ms\n",
                        peak.packets, peak.ts_unix_ms
                    ));
                }
            }
            md.push('\n');
        }

        section_json(&mut md, "Connect scan", &self.scan);
        section_json(&mut md, "Service enumeration", &self.enumeration);
        section_json(&mut md, "IDS-lite detection", &self.detection);

        if !self.audit_events.is_empty() {
            md.push_str("## Audit trail\n\n");
            md.push_str("| ts_unix_ms | module | action | result |\n");
            md.push_str("|---|---|---|---|\n");
            for ev in &self.audit_events {
                let ts = ev.get("ts_unix_ms").and_then(Value::as_u64).unwrap_or(0);
                let module = ev.get("module").and_then(Value::as_str).unwrap_or("-");
                let action = ev.get("action").and_then(Value::as_str).unwrap_or("-");
                let result = ev.get("result").and_then(Value::as_str).unwrap_or("-");
                md.push_str(&format!(
                    "| {ts} | {} | {} | {} |\n",
                    esc_cell(module),
                    esc_cell(action),
                    esc_cell(result)
                ));
            }
            md.push('\n');
        }

        append_notes_and_footer(&mut md, &self.notes);
        md
    }

    fn render_markdown_executive(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!(
            "- **Template:** executive\n- **Ticket:** {}\n- **Operator:** {}\n- **Organization:** {}\n- **Generated (unix ms):** {}\n\n",
            self.ticket_id, self.operator, self.organization, self.generated_unix_ms
        ));
        md.push_str(&self.render_markdown_executive_body());
        append_notes_and_footer(&mut md, &self.notes);
        md
    }

    fn render_markdown_executive_body(&self) -> String {
        let mut md = String::new();
        let metrics = summary_metrics(self);

        md.push_str("## Executive summary\n\n");
        md.push_str(&format!(
            "- **Open ports:** {}\n- **Enum hits:** {}\n- **Alerts:** {} (high {}, medium {}, low {})\n- **Packets observed:** {}\n- **Audit events:** {}\n\n",
            metrics.open_ports,
            metrics.enum_hits,
            metrics.alerts,
            metrics.high,
            metrics.medium,
            metrics.low,
            metrics.packets,
            metrics.audit_events
        ));

        if !self.targets.is_empty() {
            md.push_str("## Scope\n\n");
            md.push_str(&format!("- **Targets:** {}\n", self.targets.join(", ")));
            md.push_str(&format!(
                "- **Ports:** {}\n\n",
                self.ports
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        md.push_str("## Key findings\n\n");
        let findings = key_findings(self, 12);
        if findings.is_empty() {
            md.push_str("_No high-signal findings from provided inputs._\n\n");
        } else {
            for f in findings {
                md.push_str(&format!("- **{}** — {}\n", f.0, f.1));
            }
            md.push('\n');
        }
        md
    }

    fn render_markdown_compact(&self) -> String {
        let metrics = summary_metrics(self);
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!(
            "**Template:** compact · **Ticket:** {} · **Operator:** {}\n\n",
            self.ticket_id, self.operator
        ));
        md.push_str(&format!(
            "Open ports **{}** · Alerts **{}** · Packets **{}** · Enum hits **{}**\n\n",
            metrics.open_ports, metrics.alerts, metrics.packets, metrics.enum_hits
        ));
        let findings = key_findings(self, 5);
        if !findings.is_empty() {
            md.push_str("### Highlights\n\n");
            for f in findings {
                md.push_str(&format!("- {}\n", f.1));
            }
            md.push('\n');
        }
        append_notes_and_footer(&mut md, &self.notes);
        md
    }

    fn wrap_html(
        &self,
        template: &str,
        subtitle: &str,
        kpis: &str,
        charts: &str,
        timeline: &str,
        details: &str,
    ) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
:root {{
  --bg: #eef1f4;
  --fg: #12202c;
  --muted: #5b6b78;
  --card: #ffffff;
  --accent: #0f766e;
  --accent-2: #b45309;
  --accent-3: #1d4ed8;
  --danger: #b91c1c;
  --warn: #a16207;
  --ok: #047857;
  --border: #c9d2db;
  --mono: "Cascadia Code", "Consolas", ui-monospace, monospace;
  --sans: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background:
    radial-gradient(1200px 500px at 10% -10%, #d7ebe8 0%, transparent 55%),
    radial-gradient(900px 400px at 100% 0%, #f3e7d5 0%, transparent 50%),
    linear-gradient(180deg, #e8edf2 0%, var(--bg) 45%);
  color: var(--fg);
  font-family: var(--sans);
  line-height: 1.5;
}}
main {{
  max-width: 1040px;
  margin: 1.5rem auto 3rem;
  padding: 0 1rem;
}}
.panel {{
  background: var(--card);
  border: 1px solid var(--border);
  padding: 1.35rem 1.5rem;
  margin-bottom: 1rem;
}}
header.panel h1 {{
  margin: 0 0 .35rem;
  color: var(--accent);
  font-size: 1.65rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}}
.sub {{ color: var(--muted); font-size: .95rem; margin: 0; }}
.badge {{
  display: inline-block;
  margin-left: .5rem;
  padding: .1rem .45rem;
  border: 1px solid var(--border);
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .04em;
  color: var(--muted);
  vertical-align: middle;
}}
.meta-row {{
  display: flex;
  flex-wrap: wrap;
  gap: .75rem 1.25rem;
  margin-top: 1rem;
  color: var(--muted);
  font-size: .9rem;
}}
.meta-row strong {{ color: var(--fg); font-weight: 600; }}
.kpis {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: .75rem;
  margin-bottom: 1rem;
}}
.kpi {{
  background: var(--card);
  border: 1px solid var(--border);
  padding: .9rem 1rem;
}}
.kpi .label {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }}
.kpi .value {{ font-size: 1.65rem; font-weight: 700; margin-top: .15rem; font-variant-numeric: tabular-nums; }}
.charts {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: .75rem;
  margin-bottom: 1rem;
}}
.chart {{
  background: var(--card);
  border: 1px solid var(--border);
  padding: 1rem 1.1rem 1.15rem;
}}
.chart h3 {{
  margin: 0 0 .75rem;
  font-size: .95rem;
  color: var(--accent);
  font-weight: 650;
}}
.chart svg {{ width: 100%; height: auto; display: block; }}
.chart .empty {{ color: var(--muted); font-size: .9rem; margin: 0; }}
.timeline-panel h2 {{
  margin: 0 0 .85rem;
  color: var(--accent);
  font-size: 1.15rem;
}}
.timeline-rail {{
  width: 100%;
  height: auto;
  display: block;
  margin-bottom: 1rem;
}}
.timeline {{
  list-style: none;
  margin: 0;
  padding: 0;
  border-left: 2px solid var(--border);
}}
.timeline li {{
  position: relative;
  padding: 0 0 1rem 1.15rem;
}}
.timeline li:last-child {{ padding-bottom: 0; }}
.timeline li::before {{
  content: "";
  position: absolute;
  left: -5px;
  top: .45rem;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
}}
.timeline li[data-kind="alert"]::before {{ background: var(--danger); }}
.timeline li[data-kind="audit"]::before {{ background: var(--accent-3); }}
.timeline li[data-kind="note"]::before {{ background: var(--accent-2); }}
.timeline li[data-kind="system"]::before {{ background: var(--muted); }}
.timeline time {{
  display: block;
  font-family: var(--mono);
  font-size: .78rem;
  color: var(--muted);
}}
.timeline .tl-title {{
  font-weight: 650;
  margin: .1rem 0;
}}
.timeline .tl-detail {{
  color: var(--muted);
  font-size: .9rem;
}}
.timeline .tl-kind {{
  display: inline-block;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .04em;
  color: var(--muted);
  margin-right: .4rem;
}}
.details h1 {{ display: none; }}
.details h2 {{
  color: var(--accent);
  font-size: 1.15rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: .35rem;
  margin-top: 1.4rem;
}}
.details code, .details pre, .details td, .details th {{ font-family: var(--mono); font-size: .86rem; }}
.details pre {{
  background: #12202c;
  color: #e8eef3;
  padding: 1rem;
  overflow: auto;
}}
.details table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
.details th, .details td {{ border: 1px solid var(--border); padding: .4rem .55rem; text-align: left; }}
.details th {{ background: #f4f7f9; }}
.details .meta {{ color: var(--muted); }}
footer {{
  margin-top: .5rem;
  color: var(--muted);
  font-size: .85rem;
  text-align: center;
}}
@media (max-width: 640px) {{
  .kpi .value {{ font-size: 1.35rem; }}
}}
</style>
</head>
<body>
<main>
<header class="panel">
  <h1>{title}<span class="badge">{template}</span></h1>
  <p class="sub">{subtitle}</p>
  <div class="meta-row">
    <span><strong>Ticket</strong> {ticket}</span>
    <span><strong>Operator</strong> {operator}</span>
    <span><strong>Org</strong> {org}</span>
    <span><strong>Generated</strong> {generated}</span>
  </div>
</header>
<section class="kpis" aria-label="Summary metrics">
{kpis}
</section>
<section class="charts" aria-label="Charts">
{charts}
</section>
{timeline}
<section class="panel details">
{details}
</section>
<footer>Devil Eye evidence pack — authorized use only. No exploit payloads included.</footer>
</main>
</body>
</html>
"#,
            title = html_escape(&self.title),
            template = html_escape(template),
            subtitle = html_escape(subtitle),
            ticket = html_escape(&self.ticket_id),
            operator = html_escape(&self.operator),
            org = if self.organization.is_empty() {
                "—".into()
            } else {
                html_escape(&self.organization)
            },
            generated = self.generated_unix_ms,
            kpis = kpis,
            charts = charts,
            timeline = timeline,
            details = details,
        )
    }
}

fn section_json(md: &mut String, title: &str, value: &Option<Value>) {
    md.push_str(&format!("## {title}\n\n"));
    match value {
        Some(v) => {
            let pretty = serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into());
            md.push_str("```json\n");
            md.push_str(&pretty);
            md.push_str("\n```\n\n");
            // Quick bullets for common shapes.
            if let Some(open) = v.get("open").and_then(Value::as_array) {
                md.push_str(&format!("- Open ports reported: **{}**\n\n", open.len()));
            }
            if let Some(alerts) = v.get("alerts").and_then(Value::as_array) {
                md.push_str(&format!("- Alerts raised: **{}**\n\n", alerts.len()));
            }
            if let Some(results) = v.get("results").and_then(Value::as_array) {
                let openish = results
                    .iter()
                    .filter(|r| r.get("state").and_then(Value::as_str) == Some("open"))
                    .count();
                md.push_str(&format!(
                    "- Enum results: **{}** (openish **{openish}**)\n\n",
                    results.len()
                ));
            }
        }
        None => md.push_str("_Not provided._\n\n"),
    }
}

fn append_notes_and_footer(md: &mut String, notes: &[String]) {
    if !notes.is_empty() {
        md.push_str("## Notes\n\n");
        for n in notes {
            md.push_str(&format!("- {}\n", n));
        }
        md.push('\n');
    }
    md.push_str("---\n\n");
    md.push_str(
        "_Generated by Devil Eye. Authorized-use evidence only. No exploit payloads included._\n",
    );
}

#[derive(Debug, Default)]
struct SummaryMetrics {
    open_ports: u64,
    enum_hits: u64,
    alerts: u64,
    high: u64,
    medium: u64,
    low: u64,
    packets: u64,
    audit_events: u64,
}

fn summary_metrics(report: &EngagementReport) -> SummaryMetrics {
    let open_ports = report
        .scan
        .as_ref()
        .and_then(|v| v.get("open"))
        .and_then(Value::as_array)
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    let enum_hits = report
        .enumeration
        .as_ref()
        .and_then(|v| v.get("results"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|r| r.get("state").and_then(Value::as_str) == Some("open"))
                .count() as u64
        })
        .unwrap_or(0);
    let mut high = 0u64;
    let mut medium = 0u64;
    let mut low = 0u64;
    let alerts = report
        .detection
        .as_ref()
        .and_then(|v| v.get("alerts"))
        .and_then(Value::as_array)
        .map(|a| {
            for al in a {
                match al.get("severity").and_then(Value::as_str) {
                    Some("high") => high += 1,
                    Some("medium") => medium += 1,
                    Some("low") => low += 1,
                    _ => {}
                }
            }
            a.len() as u64
        })
        .unwrap_or(0);
    let packets = report
        .pcap_summary
        .as_ref()
        .map(|p| p.packets)
        .or_else(|| {
            report
                .detection
                .as_ref()
                .and_then(|v| v.get("packets"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0);
    SummaryMetrics {
        open_ports,
        enum_hits,
        alerts,
        high,
        medium,
        low,
        packets,
        audit_events: report.audit_events.len() as u64,
    }
}

/// Return (label, detail) findings for executive/compact templates.
fn key_findings(report: &EngagementReport, limit: usize) -> Vec<(String, String)> {
    let mut out = Vec::new();

    if let Some(scan) = &report.scan {
        if let Some(open) = scan.get("open").and_then(Value::as_array) {
            for row in open.iter().take(limit) {
                let ip = row.get("ip").and_then(Value::as_str).unwrap_or("?");
                let port = row
                    .get("port")
                    .and_then(Value::as_u64)
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into());
                out.push(("Open port".into(), format!("{ip}:{port}")));
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }

    if let Some(det) = &report.detection {
        if let Some(alerts) = det.get("alerts").and_then(Value::as_array) {
            let mut sorted: Vec<&Value> = alerts.iter().collect();
            sorted.sort_by_key(|a| match a.get("severity").and_then(Value::as_str) {
                Some("high") => 0,
                Some("medium") => 1,
                Some("low") => 2,
                _ => 3,
            });
            for a in sorted {
                if out.len() >= limit {
                    break;
                }
                let rule = a.get("rule").and_then(Value::as_str).unwrap_or("alert");
                let sev = a.get("severity").and_then(Value::as_str).unwrap_or("-");
                let src = a.get("src").and_then(Value::as_str).unwrap_or("-");
                let detail = a.get("detail").and_then(Value::as_str).unwrap_or("");
                out.push((
                    format!("Alert ({sev})"),
                    format!("{rule} src={src} {detail}").trim().to_string(),
                ));
            }
        }
    }

    out
}

const MAX_TIMELINE_EVENTS: usize = 200;

fn build_timeline(
    generated_unix_ms: u64,
    audit_events: &[Value],
    scan: &Option<Value>,
    enumeration: &Option<Value>,
    detection: &Option<Value>,
    pcap: &Option<PcapSummary>,
    notes: &[String],
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for ev in audit_events {
        let ts = ev.get("ts_unix_ms").and_then(Value::as_u64).unwrap_or(0);
        let module = ev.get("module").and_then(Value::as_str).unwrap_or("audit");
        let action = ev.get("action").and_then(Value::as_str).unwrap_or("-");
        let result = ev.get("result").and_then(Value::as_str).unwrap_or("-");
        events.push(TimelineEvent {
            ts_unix_ms: ts,
            kind: "audit".into(),
            title: format!("{module} / {action}"),
            detail: format!("result={result}"),
        });
    }

    if let Some(det) = detection {
        if let Some(alerts) = det.get("alerts").and_then(Value::as_array) {
            for a in alerts {
                let ts = a.get("ts_unix_ms").and_then(Value::as_u64).unwrap_or(0);
                let rule = a.get("rule").and_then(Value::as_str).unwrap_or("alert");
                let sev = a.get("severity").and_then(Value::as_str).unwrap_or("-");
                let src = a.get("src").and_then(Value::as_str).unwrap_or("-");
                let detail = a.get("detail").and_then(Value::as_str).unwrap_or("");
                events.push(TimelineEvent {
                    ts_unix_ms: ts,
                    kind: "alert".into(),
                    title: format!("{sev}: {rule}"),
                    detail: format!("src={src} {detail}").trim().to_string(),
                });
            }
        }
        if let Some(packets) = det.get("packets").and_then(Value::as_u64) {
            events.push(TimelineEvent {
                ts_unix_ms: generated_unix_ms.saturating_sub(2),
                kind: "system".into(),
                title: "IDS-lite detection complete".into(),
                detail: format!("{packets} packets processed"),
            });
        }
    }

    if let Some(s) = scan {
        let open = s
            .get("open")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let closed = s
            .get("closed_or_filtered")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        events.push(TimelineEvent {
            ts_unix_ms: generated_unix_ms.saturating_sub(3),
            kind: "scan".into(),
            title: "Connect scan results ingested".into(),
            detail: format!("open={open} closed_or_filtered={closed}"),
        });
    }

    if let Some(e) = enumeration {
        let n = e
            .get("results")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        events.push(TimelineEvent {
            ts_unix_ms: generated_unix_ms.saturating_sub(2),
            kind: "enum".into(),
            title: "Service enumeration ingested".into(),
            detail: format!("{n} results"),
        });
    }

    if let Some(p) = pcap {
        if let Some(first) = p.first_ts_unix_ms {
            events.push(TimelineEvent {
                ts_unix_ms: first,
                kind: "capture".into(),
                title: "PCAP window start".into(),
                detail: format!("{} (first packet)", p.path),
            });
        }
        if let Some(peak) = p.peak_bucket() {
            if peak.packets > 0 {
                events.push(TimelineEvent {
                    ts_unix_ms: peak.ts_unix_ms,
                    kind: "capture".into(),
                    title: "PCAP traffic peak".into(),
                    detail: format!(
                        "{} packets in bucket (tcp={} udp={} app={})",
                        peak.packets, peak.tcp, peak.udp, peak.app
                    ),
                });
            }
        }
        if let Some(last) = p.last_ts_unix_ms {
            events.push(TimelineEvent {
                ts_unix_ms: last,
                kind: "capture".into(),
                title: "PCAP window end".into(),
                detail: format!("{} ({} packets total)", p.path, p.packets),
            });
        } else {
            events.push(TimelineEvent {
                ts_unix_ms: generated_unix_ms.saturating_sub(4),
                kind: "capture".into(),
                title: "PCAP summarized".into(),
                detail: format!("{} ({} packets)", p.path, p.packets),
            });
        }
    }

    for (i, note) in notes.iter().enumerate() {
        events.push(TimelineEvent {
            ts_unix_ms: generated_unix_ms.saturating_sub(1).saturating_add(i as u64),
            kind: "note".into(),
            title: "Operator note".into(),
            detail: note.clone(),
        });
    }

    events.push(TimelineEvent {
        ts_unix_ms: generated_unix_ms,
        kind: "system".into(),
        title: "Evidence pack assembled".into(),
        detail: "Markdown/HTML/JSON report generated".into(),
    });

    events.sort_by(|a, b| {
        a.ts_unix_ms
            .cmp(&b.ts_unix_ms)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.title.cmp(&b.title))
    });
    if events.len() > MAX_TIMELINE_EVENTS {
        events.truncate(MAX_TIMELINE_EVENTS);
    }
    events
}

fn html_timeline_limited(report: &EngagementReport, max: usize) -> String {
    if report.timeline.is_empty() {
        return String::new();
    }
    let start = report.timeline.len().saturating_sub(max);
    let slice = &report.timeline[start..];
    html_timeline_events(slice)
}

fn html_timeline(report: &EngagementReport) -> String {
    html_timeline_events(&report.timeline)
}

fn html_timeline_events(events: &[TimelineEvent]) -> String {
    if events.is_empty() {
        return String::new();
    }

    let rail = timeline_svg_rail(events);
    let mut items = String::new();
    for ev in events {
        items.push_str(&format!(
            r#"<li data-kind="{kind}"><time>{ts}</time><div class="tl-title"><span class="tl-kind">{kind}</span>{title}</div><div class="tl-detail">{detail}</div></li>
"#,
            kind = html_escape(&ev.kind),
            ts = ev.ts_unix_ms,
            title = html_escape(&ev.title),
            detail = html_escape(&ev.detail),
        ));
    }

    format!(
        r#"<section class="panel timeline-panel" aria-label="Engagement timeline">
<h2>Timeline</h2>
{rail}
<ol class="timeline">
{items}</ol>
</section>"#,
        rail = rail,
        items = items,
    )
}

fn timeline_svg_rail(events: &[TimelineEvent]) -> String {
    if events.len() < 2 {
        return String::new();
    }
    let min_ts = events.iter().map(|e| e.ts_unix_ms).min().unwrap_or(0);
    let max_ts = events.iter().map(|e| e.ts_unix_ms).max().unwrap_or(min_ts);
    let span = max_ts.saturating_sub(min_ts).max(1);

    let width = 640.0_f64;
    let height = 48.0_f64;
    let pad = 16.0_f64;
    let usable = width - pad * 2.0;

    let mut marks = String::new();
    for ev in events {
        let x = pad + ((ev.ts_unix_ms - min_ts) as f64 / span as f64) * usable;
        let color = match ev.kind.as_str() {
            "alert" => "#b91c1c",
            "audit" => "#1d4ed8",
            "note" => "#b45309",
            "scan" | "enum" | "capture" => "#0f766e",
            _ => "#5b6b78",
        };
        marks.push_str(&format!(
            r#"<circle cx="{x:.1}" cy="24" r="5" fill="{color}"><title>{title}</title></circle>
"#,
            x = x,
            color = color,
            title = html_escape(&format!("{} — {}", ev.kind, ev.title)),
        ));
    }

    let axis_end = width - pad;
    let axis_color = "#c9d2db";
    format!(
        r#"<svg class="timeline-rail" viewBox="0 0 {width:.0} {height:.0}" role="img" aria-label="Timeline axis">
<line x1="{pad:.0}" y1="24" x2="{axis_end:.0}" y2="24" stroke="{axis_color}" stroke-width="2"/>
{marks}</svg>"#,
        width = width,
        height = height,
        pad = pad,
        axis_end = axis_end,
        axis_color = axis_color,
        marks = marks,
    )
}

struct Kpis {
    open_ports: u64,
    enum_hits: u64,
    alerts: u64,
    packets: u64,
    audit_events: u64,
}

fn collect_kpis(report: &EngagementReport) -> String {
    let open_ports = report
        .scan
        .as_ref()
        .and_then(|v| v.get("open"))
        .and_then(Value::as_array)
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    let enum_hits = report
        .enumeration
        .as_ref()
        .and_then(|v| v.get("results"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|r| r.get("state").and_then(Value::as_str) == Some("open"))
                .count() as u64
        })
        .unwrap_or(0);
    let alerts = report
        .detection
        .as_ref()
        .and_then(|v| v.get("alerts"))
        .and_then(Value::as_array)
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    let packets = report
        .pcap_summary
        .as_ref()
        .map(|p| p.packets)
        .or_else(|| {
            report
                .detection
                .as_ref()
                .and_then(|v| v.get("packets"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0);
    let kpis = Kpis {
        open_ports,
        enum_hits,
        alerts,
        packets,
        audit_events: report.audit_events.len() as u64,
    };

    [
        ("Open ports", kpis.open_ports),
        ("Enum hits", kpis.enum_hits),
        ("Alerts", kpis.alerts),
        ("Packets", kpis.packets),
        ("Audit events", kpis.audit_events),
    ]
    .iter()
    .map(|(label, value)| {
        format!(
            r#"<div class="kpi"><div class="label">{label}</div><div class="value">{value}</div></div>"#,
            label = html_escape(label),
            value = value
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn html_charts(report: &EngagementReport) -> String {
    let mut parts = Vec::new();

    if let Some(pcap) = &report.pcap_summary {
        let bars = [
            ("TCP", pcap.tcp, "#0f766e"),
            ("UDP", pcap.udp, "#1d4ed8"),
            ("DNS", pcap.dns, "#b45309"),
            ("HTTP", pcap.http, "#047857"),
            ("SSH", pcap.ssh, "#7c2d12"),
            ("TLS", pcap.tls, "#4338ca"),
            ("ARP", pcap.arp, "#0e7490"),
            ("DHCP", pcap.dhcp, "#a16207"),
        ];
        parts.push(svg_bar_chart("Capture protocol mix", &bars));
        if !pcap.timeline_buckets.is_empty() {
            parts.push(svg_packet_timeline(pcap));
        }
    }

    if let Some(det) = &report.detection {
        if let Some(alerts) = det.get("alerts").and_then(Value::as_array) {
            let mut by_sev: std::collections::BTreeMap<String, u64> =
                std::collections::BTreeMap::new();
            let mut by_rule: std::collections::BTreeMap<String, u64> =
                std::collections::BTreeMap::new();
            for a in alerts {
                let sev = a
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                *by_sev.entry(sev).or_default() += 1;
                let rule = a
                    .get("rule")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                *by_rule.entry(rule).or_default() += 1;
            }

            let sev_colors = |s: &str| -> &'static str {
                match s {
                    "high" => "#b91c1c",
                    "medium" => "#a16207",
                    "low" => "#047857",
                    _ => "#5b6b78",
                }
            };
            let sev_bars: Vec<(String, u64, &str)> = by_sev
                .into_iter()
                .map(|(k, v)| {
                    let color = sev_colors(&k);
                    (k, v, color)
                })
                .collect();
            let sev_refs: Vec<(&str, u64, &str)> = sev_bars
                .iter()
                .map(|(k, v, c)| (k.as_str(), *v, *c))
                .collect();
            if !sev_refs.is_empty() {
                parts.push(svg_bar_chart("Alert severity", &sev_refs));
            }

            let mut rule_sorted: Vec<(String, u64)> = by_rule.into_iter().collect();
            rule_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            rule_sorted.truncate(8);
            let rule_bars: Vec<(String, u64, &str)> = rule_sorted
                .into_iter()
                .map(|(k, v)| (k, v, "#0f766e"))
                .collect();
            let rule_refs: Vec<(&str, u64, &str)> = rule_bars
                .iter()
                .map(|(k, v, c)| (k.as_str(), *v, *c))
                .collect();
            if !rule_refs.is_empty() {
                parts.push(svg_bar_chart("Top detection rules", &rule_refs));
            }
        }
    }

    if let Some(scan) = &report.scan {
        let open = scan
            .get("open")
            .and_then(Value::as_array)
            .map(|a| a.len() as u64)
            .unwrap_or(0);
        let closed = scan
            .get("closed_or_filtered")
            .and_then(Value::as_u64)
            .or_else(|| {
                let hosts = scan.get("hosts_scanned").and_then(Value::as_u64)?;
                let ports = scan
                    .get("ports_per_host")
                    .or_else(|| scan.get("ports_scanned"))
                    .and_then(Value::as_u64)?;
                Some(hosts.saturating_mul(ports).saturating_sub(open))
            })
            .unwrap_or(0);
        if open > 0 || closed > 0 {
            parts.push(svg_bar_chart(
                "Connect scan results",
                &[
                    ("Open", open, "#047857"),
                    ("Closed/filtered", closed, "#5b6b78"),
                ],
            ));
        }
    }

    if parts.is_empty() {
        return r#"<div class="chart"><h3>Charts</h3><p class="empty">No chartable module outputs yet. Add --scan-json, --detect-json, and/or --pcap.</p></div>"#.into();
    }
    parts.join("\n")
}

/// Horizontal SVG bar chart (offline-friendly, no JS).
fn svg_bar_chart(title: &str, items: &[(&str, u64, &str)]) -> String {
    let max = items.iter().map(|(_, v, _)| *v).max().unwrap_or(0).max(1);
    let row_h = 28.0_f64;
    let label_w = 118.0_f64;
    let bar_max_w = 220.0_f64;
    let height = 24.0 + row_h * items.len() as f64;
    let width = label_w + bar_max_w + 56.0;

    let mut bars = String::new();
    for (i, (label, value, color)) in items.iter().enumerate() {
        let y = 8.0 + i as f64 * row_h;
        let w = (*value as f64 / max as f64) * bar_max_w;
        bars.push_str(&format!(
            r#"<text x="0" y="{ty:.1}" class="lbl">{label}</text>
<rect x="{lx:.1}" y="{y:.1}" width="{w:.1}" height="16" fill="{color}" rx="2"/>
<text x="{vx:.1}" y="{ty:.1}" class="val">{value}</text>
"#,
            ty = y + 12.0,
            lx = label_w,
            vx = label_w + w + 8.0,
            label = html_escape(label),
            value = value,
            color = color,
            y = y,
            w = w.max(2.0),
        ));
    }

    format!(
        r#"<div class="chart">
<h3>{title}</h3>
<svg viewBox="0 0 {width:.0} {height:.0}" role="img" aria-label="{title}">
<style>
  .lbl {{ font: 12px ui-sans-serif, system-ui, sans-serif; fill: #12202c; }}
  .val {{ font: 12px ui-monospace, monospace; fill: #5b6b78; }}
</style>
{bars}</svg>
</div>"#,
        title = html_escape(title),
        width = width,
        height = height,
        bars = bars,
    )
}

/// Create empty equal-width PCAP timeline buckets covering `[first, last]`.
pub fn allocate_pcap_buckets(
    first_ts: u64,
    last_ts: u64,
    bucket_count: usize,
) -> Vec<PcapTimelineBucket> {
    let n = bucket_count.clamp(1, 128);
    let span = last_ts.saturating_sub(first_ts).max(1);
    let mut buckets = Vec::with_capacity(n);
    for i in 0..n {
        let start = first_ts + (span.saturating_mul(i as u64) / n as u64);
        buckets.push(PcapTimelineBucket {
            ts_unix_ms: start,
            packets: 0,
            tcp: 0,
            udp: 0,
            app: 0,
        });
    }
    buckets
}

/// Map a packet timestamp into a bucket index for an allocated timeline.
pub fn pcap_bucket_index(ts: u64, first_ts: u64, last_ts: u64, bucket_count: usize) -> usize {
    let n = bucket_count.clamp(1, 128);
    if last_ts <= first_ts {
        return 0;
    }
    let span = last_ts - first_ts;
    let rel = ts.saturating_sub(first_ts).min(span);
    let idx = ((rel as u128) * (n as u128) / (span as u128 + 1)) as usize;
    idx.min(n - 1)
}

fn svg_packet_timeline(pcap: &PcapSummary) -> String {
    let buckets = &pcap.timeline_buckets;
    if buckets.is_empty() {
        return String::new();
    }
    let max = buckets.iter().map(|b| b.packets).max().unwrap_or(0).max(1);
    let width = 640.0_f64;
    let height = 120.0_f64;
    let pad_x = 28.0_f64;
    let pad_y = 18.0_f64;
    let usable_w = width - pad_x * 2.0;
    let usable_h = height - pad_y * 2.0;
    let gap = 2.0_f64;
    let bar_w = ((usable_w / buckets.len() as f64) - gap).max(2.0);

    let mut bars = String::new();
    let bar_color = "#0f766e";
    for (i, b) in buckets.iter().enumerate() {
        let h = (b.packets as f64 / max as f64) * usable_h;
        let x = pad_x + i as f64 * (bar_w + gap);
        let y = pad_y + (usable_h - h);
        bars.push_str(&format!(
            r#"<rect x="{x:.1}" y="{y:.1}" width="{bar_w:.1}" height="{h:.1}" fill="{bar_color}"><title>{title}</title></rect>
"#,
            title = html_escape(&format!(
                "@{} ms: {} packets (tcp={} udp={} app={})",
                b.ts_unix_ms, b.packets, b.tcp, b.udp, b.app
            )),
            h = h.max(1.0),
            bar_color = bar_color,
        ));
    }

    let axis_color = "#c9d2db";
    format!(
        r#"<div class="chart">
<h3>Packet timeline</h3>
<svg viewBox="0 0 {width:.0} {height:.0}" role="img" aria-label="Packet timeline">
<line x1="{pad_x:.0}" y1="{base:.0}" x2="{end:.0}" y2="{base:.0}" stroke="{axis_color}" stroke-width="1"/>
{bars}</svg>
</div>"#,
        width = width,
        height = height,
        pad_x = pad_x,
        base = pad_y + usable_h,
        end = width - pad_x,
        axis_color = axis_color,
        bars = bars,
    )
}

fn esc_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn markdownish_to_html(md: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    let mut in_table = false;
    let mut in_list = false;

    for line in md.lines() {
        if line.starts_with("```") {
            if in_code {
                out.push_str("</code></pre>\n");
                in_code = false;
            } else {
                if in_list {
                    out.push_str("</ul>\n");
                    in_list = false;
                }
                if in_table {
                    out.push_str("</table>\n");
                    in_table = false;
                }
                out.push_str("<pre><code>");
                in_code = true;
            }
            continue;
        }
        if in_code {
            out.push_str(&html_escape(line));
            out.push('\n');
            continue;
        }

        if line.starts_with("|") && line.contains('|') {
            if line.contains("---") {
                continue;
            }
            let cells: Vec<&str> = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect();
            if !in_table {
                if in_list {
                    out.push_str("</ul>\n");
                    in_list = false;
                }
                out.push_str("<table>\n");
                out.push_str("<tr>");
                for c in &cells {
                    out.push_str(&format!("<th>{}</th>", html_escape(c)));
                }
                out.push_str("</tr>\n");
                in_table = true;
            } else {
                out.push_str("<tr>");
                for c in &cells {
                    out.push_str(&format!("<td>{}</td>", html_escape(c)));
                }
                out.push_str("</tr>\n");
            }
            continue;
        } else if in_table {
            out.push_str("</table>\n");
            in_table = false;
        }

        if let Some(rest) = line.strip_prefix("# ") {
            if in_list {
                out.push_str("</ul>\n");
                in_list = false;
            }
            out.push_str(&format!("<h1>{}</h1>\n", html_escape(rest)));
        } else if let Some(rest) = line.strip_prefix("## ") {
            if in_list {
                out.push_str("</ul>\n");
                in_list = false;
            }
            out.push_str(&format!("<h2>{}</h2>\n", html_escape(rest)));
        } else if let Some(rest) = line.strip_prefix("- ") {
            if !in_list {
                out.push_str("<ul>\n");
                in_list = true;
            }
            out.push_str(&format!("<li>{}</li>\n", inline_md(rest)));
        } else if line.trim().is_empty() {
            if in_list {
                out.push_str("</ul>\n");
                in_list = false;
            }
        } else if line.starts_with("---") {
            if in_list {
                out.push_str("</ul>\n");
                in_list = false;
            }
            out.push_str("<hr/>\n");
        } else {
            if in_list {
                out.push_str("</ul>\n");
                in_list = false;
            }
            out.push_str(&format!("<p class=\"meta\">{}</p>\n", inline_md(line)));
        }
    }
    if in_code {
        out.push_str("</code></pre>\n");
    }
    if in_list {
        out.push_str("</ul>\n");
    }
    if in_table {
        out.push_str("</table>\n");
    }
    out
}

fn inline_md(s: &str) -> String {
    // Very small subset: **bold** and `code`
    let mut out = html_escape(s);
    // bold
    while let Some(start) = out.find("**") {
        if let Some(end_rel) = out[start + 2..].find("**") {
            let end = start + 2 + end_rel;
            let inner = out[start + 2..end].to_string();
            let replacement = format!("<strong>{inner}</strong>");
            out.replace_range(start..end + 2, &replacement);
        } else {
            break;
        }
    }
    // code
    let parts: Vec<&str> = out.split('`').collect();
    if parts.len() > 1 {
        let mut rebuilt = String::new();
        for (i, p) in parts.iter().enumerate() {
            if i % 2 == 1 {
                rebuilt.push_str(&format!("<code>{p}</code>"));
            } else {
                rebuilt.push_str(p);
            }
        }
        out = rebuilt;
    }
    out
}

/// Load a JSON file into a Value.
pub fn load_json_file(path: &Path) -> Result<Value> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid JSON in {}", path.display()))
}

/// Load JSONL audit events (best-effort; skip bad lines).
pub fn load_audit_jsonl(path: &Path) -> Result<Vec<Value>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read audit log {}", path.display()))?;
    let mut events = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            events.push(v);
        }
    }
    Ok(events)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_contains_ticket() {
        let report = EngagementReport::assemble(ReportInputs {
            scope: Some(Scope {
                ticket_id: "T-1".into(),
                operator: "op".into(),
                organization: "lab".into(),
                authorized: true,
                targets: vec!["127.0.0.1".into()],
                exclude: vec![],
                ports: vec![80],
                max_pps: 10,
                connect_timeout_ms: 500,
                max_hosts: 8,
                valid_until_unix: None,
            }),
            scan_json: Some(serde_json::json!({"open":[{"ip":"127.0.0.1","port":80}]})),
            ..Default::default()
        });
        let md = report.to_markdown();
        assert!(md.contains("T-1"));
        assert!(md.contains("Open ports reported"));
        let html = report.to_html();
        assert!(html.contains("<html"));
        assert!(html.contains("T-1"));
        assert!(html.contains("class=\"kpis\""));
        assert!(html.contains("Connect scan results"));
        assert!(html.contains("<svg"));
        assert!(md.contains("## Timeline"));
        assert!(html.contains("timeline-panel"));
        assert!(!report.timeline.is_empty());
    }

    #[test]
    fn timeline_merges_audit_and_alerts() {
        let report = EngagementReport::assemble(ReportInputs {
            detect_json: Some(serde_json::json!({
                "module": "detect/ids_lite",
                "packets": 3,
                "alerts": [
                    {"ts_unix_ms": 100, "rule": "rare_port", "severity": "medium", "src": "1.2.3.4", "detail": "31337"}
                ]
            })),
            audit_events: vec![serde_json::json!({
                "ts_unix_ms": 50,
                "module": "detect/ids_lite",
                "action": "start",
                "result": "ok"
            })],
            notes: vec!["lab only".into()],
            ..Default::default()
        });
        assert!(report.timeline.iter().any(|e| e.kind == "alert"));
        assert!(report.timeline.iter().any(|e| e.kind == "audit"));
        assert!(report.timeline.iter().any(|e| e.kind == "note"));
        assert!(report
            .timeline
            .iter()
            .any(|e| e.title.contains("Evidence pack")));
        let md = report.to_markdown();
        assert!(md.contains("rare_port") || md.contains("alert"));
        let html = report.to_html();
        assert!(html.contains("class=\"timeline\""));
        assert!(html.contains("timeline-rail") || html.contains("Timeline"));
    }

    #[test]
    fn html_charts_detection_and_pcap() {
        let report = EngagementReport::assemble(ReportInputs {
            detect_json: Some(serde_json::json!({
                "module": "detect/ids_lite",
                "packets": 12,
                "alerts": [
                    {"rule": "tcp_syn_scan", "severity": "high", "src": "1.1.1.1", "detail": "x"},
                    {"rule": "rare_port", "severity": "medium", "src": "1.1.1.1", "detail": "y"},
                    {"rule": "rare_port", "severity": "medium", "src": "2.2.2.2", "detail": "z"}
                ]
            })),
            pcap_summary: Some(PcapSummary {
                path: "lab.pcap".into(),
                packets: 100,
                decode_ok: 98,
                decode_fail: 2,
                tcp: 60,
                udp: 30,
                dns: 8,
                http: 2,
                ssh: 1,
                tls: 4,
                arp: 3,
                dhcp: 2,
                first_ts_unix_ms: Some(1_000),
                last_ts_unix_ms: Some(1_900),
                timeline_buckets: vec![
                    PcapTimelineBucket {
                        ts_unix_ms: 1_000,
                        packets: 10,
                        tcp: 6,
                        udp: 4,
                        app: 2,
                    },
                    PcapTimelineBucket {
                        ts_unix_ms: 1_450,
                        packets: 40,
                        tcp: 30,
                        udp: 10,
                        app: 5,
                    },
                    PcapTimelineBucket {
                        ts_unix_ms: 1_700,
                        packets: 20,
                        tcp: 12,
                        udp: 8,
                        app: 3,
                    },
                ],
            }),
            ..Default::default()
        });
        let html = report.to_html();
        assert!(html.contains("Alert severity"));
        assert!(html.contains("Top detection rules"));
        assert!(html.contains("Capture protocol mix"));
        assert!(html.contains("Packet timeline"));
        assert!(html.contains("tcp_syn_scan") || html.contains("rare_port"));
        assert!(report
            .timeline
            .iter()
            .any(|e| e.title.contains("PCAP traffic peak")));
    }

    #[test]
    fn pcap_bucket_helpers() {
        let buckets = allocate_pcap_buckets(100, 199, 4);
        assert_eq!(buckets.len(), 4);
        assert_eq!(buckets[0].ts_unix_ms, 100);
        assert_eq!(pcap_bucket_index(100, 100, 199, 4), 0);
        assert_eq!(pcap_bucket_index(199, 100, 199, 4), 3);
    }

    #[test]
    fn templates_executive_and_compact() {
        let report = EngagementReport::assemble(ReportInputs {
            scan_json: Some(serde_json::json!({
                "open": [{"ip":"10.0.0.1","port":22}],
                "closed_or_filtered": 3
            })),
            detect_json: Some(serde_json::json!({
                "packets": 9,
                "alerts": [
                    {"ts_unix_ms": 1, "rule": "tcp_syn_scan", "severity": "high", "src": "1.1.1.1", "detail": "scan"}
                ]
            })),
            notes: vec!["authorized lab".into()],
            ..Default::default()
        });

        let exec = report.to_markdown_template(ReportTemplate::Executive);
        assert!(exec.contains("Template:** executive") || exec.contains("executive"));
        assert!(exec.contains("Executive summary"));
        assert!(exec.contains("Key findings"));
        assert!(!exec.contains("```json"));

        let compact = report.to_markdown_template(ReportTemplate::Compact);
        assert!(compact.contains("compact"));
        assert!(compact.contains("Open ports"));

        let html = report.to_html_template(ReportTemplate::Executive);
        assert!(html.contains("badge") || html.contains("executive"));
        assert!(html.contains("Executive findings") || html.contains("executive"));
    }
}
