//! Engagement report CLI — assemble Markdown/HTML evidence packs.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::audit::AuditLog;
use crate::capture::OfflineSource;
use crate::cli::ReportArgs;
use crate::decode::decode_packet;
use crate::packet::{AppInfo, TransportInfo};
use crate::report::{
    allocate_pcap_buckets, load_audit_jsonl, load_json_file, pcap_bucket_index, EngagementReport,
    PcapSummary, ReportInputs, ReportTemplate,
};
use crate::scope::Scope;

/// Build an evidence pack from prior module JSON outputs (+ optional PCAP).
pub fn run(args: &ReportArgs) -> Result<()> {
    if args.out_md.is_none() && args.out_html.is_none() && args.out_json.is_none() {
        bail!("specify at least one of --out-md / --out-html / --out-json");
    }

    let scope = match &args.scope {
        Some(path) => Some(Scope::load(path)?),
        None => None,
    };

    let operator = scope
        .as_ref()
        .map(|s| s.operator.clone())
        .unwrap_or_else(|| "anonymous".into());
    let ticket = scope
        .as_ref()
        .map(|s| s.ticket_id.clone())
        .unwrap_or_else(|| "unscoped".into());

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "report/evidence",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "scope": args.scope.as_ref().map(|p| p.display().to_string()),
            "scan_json": args.scan_json.as_ref().map(|p| p.display().to_string()),
            "enum_json": args.enum_json.as_ref().map(|p| p.display().to_string()),
            "detect_json": args.detect_json.as_ref().map(|p| p.display().to_string()),
            "pcap": args.pcap.as_ref().map(|p| p.display().to_string()),
            "template": args.template,
        }),
        "ok",
    )?;

    let template = ReportTemplate::parse(&args.template)?;

    let mut inputs = ReportInputs {
        scope,
        notes: args.notes.clone(),
        ..Default::default()
    };

    if let Some(path) = &args.scan_json {
        inputs.scan_json = Some(load_json_file(path)?);
    }
    if let Some(path) = &args.enum_json {
        inputs.enum_json = Some(load_json_file(path)?);
    }
    if let Some(path) = &args.detect_json {
        inputs.detect_json = Some(load_json_file(path)?);
    }
    if let Some(path) = &args.audit_in {
        inputs.audit_events = load_audit_jsonl(path)?;
    }
    if let Some(path) = &args.pcap {
        let buckets = args.pcap_timeline_buckets.unwrap_or(24);
        inputs.pcap_summary = Some(summarize_pcap(path, buckets)?);
    }

    let report = EngagementReport::assemble(inputs);

    if let Some(path) = &args.out_md {
        std::fs::write(path, report.to_markdown_template(template))
            .with_context(|| format!("failed to write {}", path.display()))?;
        eprintln!(
            "wrote Markdown {} (template={})",
            path.display(),
            template.as_str()
        );
    }
    if let Some(path) = &args.out_html {
        std::fs::write(path, report.to_html_template(template))
            .with_context(|| format!("failed to write {}", path.display()))?;
        eprintln!(
            "wrote HTML {} (template={})",
            path.display(),
            template.as_str()
        );
    }
    if let Some(path) = &args.out_json {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("wrote JSON {}", path.display());
    }

    audit.info(
        "report/evidence",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "out_md": args.out_md.as_ref().map(|p| p.display().to_string()),
            "out_html": args.out_html.as_ref().map(|p| p.display().to_string()),
            "out_json": args.out_json.as_ref().map(|p| p.display().to_string()),
            "template": template.as_str(),
        }),
        "ok",
    )?;

    Ok(())
}

fn summarize_pcap(path: &Path, bucket_count: usize) -> Result<PcapSummary> {
    let bucket_count = bucket_count.clamp(1, 128);

    // Pass 1: totals + time range.
    let mut src = OfflineSource::open(path)?;
    let mut packets = 0u64;
    let mut decode_ok = 0u64;
    let mut decode_fail = 0u64;
    let mut tcp = 0u64;
    let mut udp = 0u64;
    let mut dns = 0u64;
    let mut http = 0u64;
    let mut ssh = 0u64;
    let mut tls = 0u64;
    let mut arp = 0u64;
    let mut dhcp = 0u64;
    let mut first_ts: Option<u64> = None;
    let mut last_ts: Option<u64> = None;

    while let Some(pkt) = src.next_packet()? {
        packets += 1;
        let ts = u64::from(pkt.timestamp_secs)
            .saturating_mul(1000)
            .saturating_add(u64::from(pkt.timestamp_usecs) / 1000);
        first_ts = Some(first_ts.map_or(ts, |f| f.min(ts)));
        last_ts = Some(last_ts.map_or(ts, |l| l.max(ts)));

        match decode_packet(&pkt.data) {
            Ok(decoded) => {
                decode_ok += 1;
                match &decoded.transport {
                    Some(TransportInfo::Tcp(_)) => tcp += 1,
                    Some(TransportInfo::Udp(_)) => udp += 1,
                    _ => {}
                }
                match &decoded.app {
                    Some(AppInfo::Dns(_)) => dns += 1,
                    Some(AppInfo::Http(_)) => http += 1,
                    Some(AppInfo::Ssh(_)) => ssh += 1,
                    Some(AppInfo::Tls(_)) => tls += 1,
                    Some(AppInfo::Arp(_)) => arp += 1,
                    Some(AppInfo::Dhcp(_)) => dhcp += 1,
                    None => {}
                }
            }
            Err(_) => decode_fail += 1,
        }
    }

    // Pass 2: fill timeline buckets when we have a time window.
    let timeline_buckets = match (first_ts, last_ts) {
        (Some(first), Some(last)) => {
            let mut buckets = allocate_pcap_buckets(first, last, bucket_count);
            let mut src2 = OfflineSource::open(path)?;
            while let Some(pkt) = src2.next_packet()? {
                let ts = u64::from(pkt.timestamp_secs)
                    .saturating_mul(1000)
                    .saturating_add(u64::from(pkt.timestamp_usecs) / 1000);
                let idx = pcap_bucket_index(ts, first, last, bucket_count);
                if let Some(b) = buckets.get_mut(idx) {
                    b.packets += 1;
                    if let Ok(decoded) = decode_packet(&pkt.data) {
                        match &decoded.transport {
                            Some(TransportInfo::Tcp(_)) => b.tcp += 1,
                            Some(TransportInfo::Udp(_)) => b.udp += 1,
                            _ => {}
                        }
                        if decoded.app.is_some() {
                            b.app += 1;
                        }
                    }
                }
            }
            buckets
        }
        _ => Vec::new(),
    };

    Ok(PcapSummary {
        path: path.display().to_string(),
        packets,
        decode_ok,
        decode_fail,
        tcp,
        udp,
        dns,
        http,
        ssh,
        tls,
        arp,
        dhcp,
        first_ts_unix_ms: first_ts,
        last_ts_unix_ms: last_ts,
        timeline_buckets,
    })
}
