//! Live dashboard over offline PCAP or live capture.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::audit::AuditLog;
use crate::capture::open_source;
use crate::cli::WatchArgs;
use crate::dashboard::{
    paint_terminal, parse_serve_addr, spawn_http_server, write_html_file, DashState,
};
use crate::decode::decode_packet;
use crate::detect::{DetectConfig, Detector};
use crate::modules::export_cmd;
use crate::modules::session_cmd;
use crate::rules::RulePack;
use crate::scope::Scope;
use crate::session::{
    append_alert, attach as session_attach, heartbeat as session_heartbeat, presence_snapshot,
};
use crate::stats::TrafficStats;

/// Run the live watch dashboard.
pub fn run(args: &WatchArgs) -> Result<()> {
    let capture = args.to_capture_args();
    capture.validate()?;

    let (operator, ticket, scope_obj) = if let Some(path) = &args.scope {
        let scope = Scope::load(path)?;
        (scope.operator.clone(), scope.ticket_id.clone(), Some(scope))
    } else {
        ("anonymous".into(), "watch-no-scope".into(), None)
    };

    session_cmd::require_scope_for_session(&args.session_dir, &args.scope)?;

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "watch/dashboard",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "interface": args.interface,
            "read": args.read.as_ref().map(|p| p.display().to_string()),
            "filter": args.filter,
            "rules": args.rules.as_ref().map(|p| p.display().to_string()),
            "serve": args.serve,
            "html_out": args.html_out.as_ref().map(|p| p.display().to_string()),
            "refresh_ms": args.refresh_ms,
            "siem_format": args.siem_format,
            "siem_out": args.siem_out.as_ref().map(|p| p.display().to_string()),
            "siem_udp": args.siem_udp,
            "session_dir": args.session_dir.as_ref().map(|p| p.display().to_string()),
        }),
        "ok",
    )?;

    let mut session_attached = false;
    if let (Some(dir), Some(scope)) = (&args.session_dir, &scope_obj) {
        let st = session_attach(dir, scope, &args.session_role)?;
        session_attached = true;
        writeln!(
            io::stderr(),
            "session attached: {} ticket={} operators={}",
            st.session_id,
            st.ticket_id,
            st.operators.len()
        )?;
    }

    let mut siem = export_cmd::maybe_open_from_flags(
        "watch/dashboard",
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

    let source_label = if let Some(path) = &args.read {
        format!("pcap:{}", path.display())
    } else if let Some(iface) = &args.interface {
        format!("live:{iface}")
    } else {
        "unknown".into()
    };

    let mut cfg = DetectConfig::default();
    let mut pack_name: Option<String> = None;
    if let Some(path) = &args.rules {
        let pack = RulePack::load(path)?;
        pack_name = Some(pack.name.clone());
        cfg = pack.apply_to(cfg)?;
    }
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
    if let Some(ms) = args.alert_cooldown_ms {
        cfg.alert_cooldown_ms = ms;
    }

    let state = Arc::new(Mutex::new(DashState::new(
        source_label,
        pack_name.clone(),
        args.recent,
    )));
    if session_attached {
        if let Some(dir) = &args.session_dir {
            push_session_presence(dir, &state);
        }
    }

    if let Some(bind) = &args.serve {
        let addr = parse_serve_addr(bind)?;
        let local = spawn_http_server(
            &addr,
            Arc::clone(&state),
            Arc::clone(&running),
            args.refresh_ms,
        )?;
        writeln!(
            io::stderr(),
            "dashboard HTTP listening on http://{local}/  (API: /api/snapshot)"
        )?;
    }

    let mut source = open_source(&capture)?;
    let mut detector = Detector::new(cfg);
    let mut stats = TrafficStats::new();
    let mut packets = 0u64;
    let refresh = Duration::from_millis(args.refresh_ms.max(50));
    let mut last_paint = Instant::now()
        .checked_sub(refresh)
        .unwrap_or_else(Instant::now);
    let hb_interval = Duration::from_secs(30);
    let mut last_hb = Instant::now();

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
                    refresh_surfaces(args, &state, &mut last_paint, refresh, true)?;
                    continue;
                }
                return Err(err).context("capture error");
            }
        };

        packets += 1;
        let ts_ms = u64::from(packet.timestamp_secs)
            .saturating_mul(1000)
            .saturating_add(u64::from(packet.timestamp_usecs) / 1000);

        match decode_packet(&packet.data) {
            Ok(decoded) => {
                stats.record(&decoded, packet.data.len());
                let new_alerts = detector.observe(&decoded, ts_ms);
                if let Some(exp) = siem.as_mut() {
                    for a in &new_alerts {
                        exp.emit(a)?;
                    }
                }
                if let (Some(dir), Some(scope)) = (&args.session_dir, &scope_obj) {
                    for a in &new_alerts {
                        append_alert(dir, scope, "watch/dashboard", a)?;
                    }
                }
                if let Ok(mut st) = state.lock() {
                    st.update_traffic(stats.snapshot());
                    st.push_alerts(&new_alerts);
                }
            }
            Err(_) => {
                stats.record_raw(packet.data.len());
                if let Ok(mut st) = state.lock() {
                    st.update_traffic(stats.snapshot());
                }
            }
        }

        refresh_surfaces(args, &state, &mut last_paint, refresh, false)?;

        if let (Some(dir), Some(scope)) = (&args.session_dir, &scope_obj) {
            if last_hb.elapsed() >= hb_interval {
                let _ = session_heartbeat(dir, scope);
                push_session_presence(dir, &state);
                last_hb = Instant::now();
            }
        }
    }

    if let Ok(mut st) = state.lock() {
        st.update_traffic(stats.snapshot());
        st.set_status("complete");
    }
    // Final paint / HTML flush.
    last_paint = Instant::now()
        .checked_sub(refresh)
        .unwrap_or_else(Instant::now);
    refresh_surfaces(args, &state, &mut last_paint, refresh, true)?;

    if let Some(exp) = siem.as_mut() {
        exp.flush()?;
        writeln!(
            io::stderr(),
            "SIEM export: format={} emitted={}",
            exp.format().as_str(),
            exp.emitted()
        )?;
    }

    let snap = state
        .lock()
        .map_err(|_| anyhow::anyhow!("dashboard lock poisoned"))?
        .snapshot();

    if let Some(path) = &args.json_out {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &snap)?;
        eprintln!("wrote JSON snapshot {}", path.display());
    }

    writeln!(
        io::stderr(),
        "watch complete: packets={} alerts={} (audited -> {})",
        snap.traffic.packets,
        snap.alert_total,
        audit.path().display()
    )?;

    audit.info(
        "watch/dashboard",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "packets": snap.traffic.packets,
            "alerts": snap.alert_total,
            "rules_pack": pack_name,
        }),
        "ok",
    )?;

    // Keep HTTP server alive briefly if serving so a final poll can succeed, then stop.
    if args.serve.is_some() && !args.no_hold {
        writeln!(
            io::stderr(),
            "HTTP still serving final snapshot — Ctrl+C to exit"
        )?;
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }
    } else {
        running.store(false, Ordering::SeqCst);
    }

    Ok(())
}

fn push_session_presence(dir: &std::path::Path, state: &Arc<Mutex<DashState>>) {
    if let Ok(info) = presence_snapshot(dir) {
        if let Ok(mut st) = state.lock() {
            st.set_session(Some(info));
        }
    }
}

fn refresh_surfaces(
    args: &WatchArgs,
    state: &Arc<Mutex<DashState>>,
    last_paint: &mut Instant,
    refresh: Duration,
    force: bool,
) -> Result<()> {
    if !force && last_paint.elapsed() < refresh {
        return Ok(());
    }
    *last_paint = Instant::now();
    // Refresh operator ages / notes on each paint so the presence panel stays current.
    if let Some(dir) = &args.session_dir {
        push_session_presence(dir, state);
    }
    let snap = state
        .lock()
        .map_err(|_| anyhow::anyhow!("dashboard lock poisoned"))?
        .snapshot();
    if !args.quiet {
        paint_terminal(&snap, !args.no_clear)?;
    }
    if let Some(path) = &args.html_out {
        write_html_file(path, &snap)?;
    }
    Ok(())
}
