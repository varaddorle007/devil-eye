//! IDS-lite CLI runner over offline PCAP or live capture.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::audit::AuditLog;
use crate::capture::open_source;
use crate::cli::DetectArgs;
use crate::decode::decode_packet;
use crate::detect::{DetectConfig, Detector};
use crate::modules::export_cmd;
use crate::modules::session_cmd;
use crate::rules::RulePack;
use crate::scope::Scope;
use crate::session::{append_alert, attach as session_attach};

#[derive(Debug, Serialize)]
struct DetectReport {
    pub module: String,
    pub packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_pack: Option<String>,
    pub alerts: Vec<crate::detect::Alert>,
}

/// Run detection over a capture source described by DetectArgs.
pub fn run(args: &DetectArgs) -> Result<()> {
    let capture = args.to_capture_args();
    capture.validate()?;
    session_cmd::require_scope_for_session(&args.session_dir, &args.scope)?;

    let (operator, ticket, scope_obj) = if let Some(path) = &args.scope {
        let scope = Scope::load(path)?;
        (scope.operator.clone(), scope.ticket_id.clone(), Some(scope))
    } else {
        ("anonymous".into(), "detect-no-scope".into(), None)
    };

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "detect/ids_lite",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "interface": args.interface,
            "read": args.read.as_ref().map(|p| p.display().to_string()),
            "filter": args.filter,
            "syn_scan_ports": args.syn_scan_ports,
            "host_sweep_hosts": args.host_sweep_hosts,
            "icmp_echo_count": args.icmp_echo_count,
            "dns_unique_names": args.dns_unique_names,
            "tcp_rst_count": args.tcp_rst_count,
            "dhcp_discover_count": args.dhcp_discover_count,
            "dns_nxdomain_count": args.dns_nxdomain_count,
            "rules": args.rules.as_ref().map(|p| p.display().to_string()),
            "siem_format": args.siem_format,
            "siem_out": args.siem_out.as_ref().map(|p| p.display().to_string()),
            "siem_udp": args.siem_udp,
            "session_dir": args.session_dir.as_ref().map(|p| p.display().to_string()),
        }),
        "ok",
    )?;

    if let (Some(dir), Some(scope)) = (&args.session_dir, &scope_obj) {
        let st = session_attach(dir, scope, &args.session_role)?;
        writeln!(
            io::stderr(),
            "session attached: {} ticket={} operators={}",
            st.session_id,
            st.ticket_id,
            st.operators.len()
        )?;
    }

    let mut siem = export_cmd::maybe_open_from_flags(
        "detect/ids_lite",
        &operator,
        &ticket,
        &args.siem_format,
        args.siem_out.as_ref(),
        args.siem_udp.as_deref(),
    )?;

    let running = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&running);
    ctrlc::set_handler(move || {
        flag.store(false, Ordering::SeqCst);
    })
    .context("failed to install Ctrl+C handler")?;

    let mut source = open_source(&capture)?;
    let mut cfg = DetectConfig::default();
    let mut pack_name: Option<String> = None;
    if let Some(path) = &args.rules {
        let pack = RulePack::load(path)?;
        pack_name = Some(pack.name.clone());
        cfg = pack.apply_to(cfg)?;
    }
    // CLI flags override rule-pack values.
    if let Some(n) = args.syn_scan_ports {
        cfg.syn_scan_ports = n;
    }
    if let Some(n) = args.host_sweep_hosts {
        cfg.host_sweep_hosts = n;
    }
    if let Some(n) = args.icmp_echo_count {
        cfg.icmp_echo_count = n;
    }
    if let Some(n) = args.dns_unique_names {
        cfg.dns_unique_names = n;
    }
    if let Some(n) = args.tcp_rst_count {
        cfg.tcp_rst_count = n;
    }
    if let Some(n) = args.dhcp_discover_count {
        cfg.dhcp_discover_count = n;
    }
    if let Some(n) = args.dns_nxdomain_count {
        cfg.dns_nxdomain_count = n;
    }
    let mut detector = Detector::new(cfg);

    let mut packets = 0u64;

    while running.load(Ordering::SeqCst) {
        if let Some(limit) = args.count {
            if packets >= limit {
                break;
            }
        }

        let packet = match source.next_packet() {
            Ok(Some(pkt)) => pkt,
            Ok(None) => break,
            Err(err) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                let msg = err.to_string().to_lowercase();
                if msg.contains("timeout") || msg.contains("timed out") {
                    continue;
                }
                return Err(err).context("capture error");
            }
        };

        packets += 1;
        let ts_ms = u64::from(packet.timestamp_secs)
            .saturating_mul(1000)
            .saturating_add(u64::from(packet.timestamp_usecs) / 1000);

        if let Ok(decoded) = decode_packet(&packet.data) {
            for a in detector.observe(&decoded, ts_ms) {
                println!("[{}] {} src={} — {}", a.severity, a.rule, a.src, a.detail);
                if let Some(exp) = siem.as_mut() {
                    exp.emit(&a)?;
                }
                if let (Some(dir), Some(scope)) = (&args.session_dir, &scope_obj) {
                    append_alert(dir, scope, "detect/ids_lite", &a)?;
                }
            }
        }
    }

    if let Some(exp) = siem.as_mut() {
        exp.flush()?;
        writeln!(
            io::stderr(),
            "SIEM export: format={} emitted={}",
            exp.format().as_str(),
            exp.emitted()
        )?;
    }

    let report = DetectReport {
        module: "detect/ids_lite".into(),
        packets,
        rules_pack: pack_name.clone(),
        alerts: detector.alerts().to_vec(),
    };

    if let Some(path) = &args.json_out {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("wrote JSON report {}", path.display());
    }

    if let Some(name) = &pack_name {
        writeln!(io::stderr(), "rules pack: {name}")?;
    }

    writeln!(
        io::stderr(),
        "detect complete: packets={packets} alerts={} (audited -> {})",
        report.alerts.len(),
        audit.path().display()
    )?;

    audit.info(
        "detect/ids_lite",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "packets": packets,
            "alerts": report.alerts.len(),
            "rules_pack": pack_name,
            "siem_emitted": siem.as_ref().map(|e| e.emitted()),
        }),
        "ok",
    )?;

    Ok(())
}
