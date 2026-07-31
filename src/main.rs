//! Devil Eye — authorized cybersecurity toolkit.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;

use devil_eye::audit::AuditLog;
use devil_eye::capture::{list_interfaces, open_source};
use devil_eye::cli::{CaptureArgs, Cli, Commands};
use devil_eye::decode::decode_packet;
use devil_eye::modules::{
    self, detect_cmd, diff_cmd, enum_svc, export_cmd, import_cmd, merge_cmd, report_cmd, scan,
    session_cmd, slice_cmd, watch_cmd,
};
use devil_eye::output::{format_timestamp, print_packet, TsMode, TsState};
use devil_eye::scope::Scope;
use devil_eye::stats::TrafficStats;

fn main() {
    if let Err(err) = run() {
        eprintln!("devil-eye: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let use_color = devil_eye::banner::want_color(cli.no_color);
    match cli.command {
        Some(cmd) => {
            devil_eye::banner::maybe_print(cli.no_banner, use_color);
            dispatch(cmd)
        }
        None => run_interactive(cli.no_banner, use_color),
    }
}

fn run_interactive(no_banner: bool, use_color: bool) -> Result<()> {
    devil_eye::banner::maybe_print(no_banner, use_color);
    loop {
        match devil_eye::console::prompt_selection(use_color)? {
            None => {
                eprintln!("bye.");
                return Ok(());
            }
            Some(tokens) => {
                // Re-parse as: devil-eye <tokens...>
                let mut argv = vec!["devil-eye".to_string()];
                argv.extend(tokens);
                match Cli::try_parse_from(&argv) {
                    Ok(parsed) => match parsed.command {
                        Some(cmd) => {
                            if let Err(err) = dispatch(cmd) {
                                eprintln!("devil-eye: {err:#}");
                            }
                        }
                        None => {
                            eprintln!("pick a module command (not the bare launcher)");
                        }
                    },
                    Err(err) => {
                        // Clap help/usage goes to stderr via this Display.
                        eprintln!("{err}");
                    }
                }
                eprintln!();
            }
        }
    }
}

fn dispatch(command: Commands) -> Result<()> {
    match command {
        Commands::Capture(args) => run_capture(args),
        Commands::Scan(args) => scan::run(&args),
        Commands::Enum(args) => enum_svc::run(&args),
        Commands::Detect(args) => detect_cmd::run(&args),
        Commands::Watch(args) => watch_cmd::run(&args),
        Commands::Export(args) => export_cmd::run(&args),
        Commands::Import(args) => import_cmd::run(&args),
        Commands::Diff(args) => diff_cmd::run(&args),
        Commands::Merge(args) => merge_cmd::run(&args),
        Commands::Slice(args) => slice_cmd::run(&args),
        Commands::Session(args) => session_cmd::run(&args),
        Commands::Report(args) => report_cmd::run(&args),
        Commands::Modules => {
            modules::print_catalog();
            Ok(())
        }
    }
}

fn run_capture(args: CaptureArgs) -> Result<()> {
    args.validate()?;

    let audit = AuditLog::open(&args.audit_log);
    let (operator, ticket) = if let Some(path) = &args.scope {
        let scope = Scope::load(path)?;
        (scope.operator.clone(), scope.ticket_id.clone())
    } else {
        ("anonymous".into(), "passive-no-scope".into())
    };

    if args.list_interfaces {
        audit.info(
            "capture",
            "list_interfaces",
            &operator,
            &ticket,
            serde_json::json!({}),
            "ok",
        )?;
        return print_interfaces();
    }

    audit.info(
        "capture",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "interface": args.interface,
            "read": args.read.as_ref().map(|p| p.display().to_string()),
            "write": args.write.as_ref().map(|p| p.display().to_string()),
            "filter": args.filter,
            "count": args.count,
        }),
        "ok",
    )?;

    let running = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&running);
    ctrlc::set_handler(move || {
        flag.store(false, Ordering::SeqCst);
    })
    .context("failed to install Ctrl+C handler")?;

    let mut source = open_source(&args)?;
    let mut writer = match &args.write {
        Some(path) => Some(source.open_writer(path)?),
        None => None,
    };

    let mut stats = TrafficStats::new();
    let mut decode_failures: u64 = 0;
    let mut printed: u64 = 0;
    let stats_interval = Duration::from_secs(10);
    let mut last_stats = Instant::now();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut ts_state = TsState::new();
    let ts_mode = TsMode::from_count(args.timestamp);

    while running.load(Ordering::SeqCst) {
        if let Some(limit) = args.count {
            if printed >= limit {
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
                if is_timeout(&err) {
                    if args.stats && last_stats.elapsed() >= stats_interval {
                        stats.print_periodic(&mut io::stderr())?;
                        last_stats = Instant::now();
                    }
                    continue;
                }
                return Err(err).context("capture error");
            }
        };

        if let Some(w) = writer.as_mut() {
            w.write_packet(&packet)?;
        }

        match decode_packet(&packet.data) {
            Ok(decoded) => {
                stats.record(&decoded, packet.data.len());
                if !args.quiet {
                    print_packet(&mut out, &packet, &decoded, &args, &mut ts_state)?;
                }
                printed += 1;
            }
            Err(_) => {
                decode_failures += 1;
                stats.record_raw(packet.data.len());
                if args.verbose > 0 && !args.quiet {
                    let ts = format_timestamp(&packet, ts_mode, &mut ts_state);
                    if ts.is_empty() {
                        writeln!(
                            out,
                            "truncated-or-malformed frame ({} bytes)",
                            packet.data.len()
                        )?;
                    } else {
                        writeln!(
                            out,
                            "{ts} truncated-or-malformed frame ({} bytes)",
                            packet.data.len()
                        )?;
                    }
                }
                printed += 1;
            }
        }

        if args.stats && last_stats.elapsed() >= stats_interval {
            stats.print_periodic(&mut io::stderr())?;
            last_stats = Instant::now();
        }
    }

    if let Some(w) = writer.as_mut() {
        w.flush()?;
    }

    if let Ok(cs) = source.capture_stats() {
        stats.set_capture_stats(cs.received, cs.dropped, cs.if_dropped);
    }

    if args.stats || !args.quiet {
        stats.print_final(&mut io::stderr(), decode_failures)?;
    }

    audit.info(
        "capture",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "packets": printed,
            "decode_failures": decode_failures,
        }),
        "ok",
    )?;

    Ok(())
}

fn print_interfaces() -> Result<()> {
    let ifaces = list_interfaces()?;
    if ifaces.is_empty() {
        println!("No capture interfaces found.");
        #[cfg(target_os = "windows")]
        {
            println!("Install the Npcap runtime from https://npcap.com/ (elevated terminal).");
            println!("If this binary was built offline-only, run: .\\scripts\\build-release.ps1");
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            println!("Install libpcap and rebuild, then re-run with sufficient privileges:");
            println!("  ./scripts/build-release.sh");
            println!("  sudo ./target/release/devil-eye capture -D");
        }
        return Ok(());
    }
    for (idx, iface) in ifaces.iter().enumerate() {
        let desc = iface
            .description
            .as_deref()
            .filter(|d| !d.is_empty())
            .unwrap_or("-");
        println!("{}. {} ({})", idx + 1, iface.name, desc);
        for addr in &iface.addresses {
            println!("\t{addr}");
        }
    }
    Ok(())
}

fn is_timeout(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        let msg = e.to_string().to_lowercase();
        msg.contains("timeout") || msg.contains("timed out")
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::CommandFactory;
    use devil_eye::cli::{CaptureArgs, Cli};

    #[test]
    fn cli_parses_help() {
        Cli::command().debug_assert();
    }

    #[test]
    fn rejects_conflicting_modes() {
        let args = CaptureArgs {
            list_interfaces: false,
            interface: Some("eth0".into()),
            read: Some(PathBuf::from("a.pcap")),
            write: None,
            count: None,
            filter: None,
            numeric: false,
            timestamp: 0,
            verbose: 0,
            stats: false,
            quiet: false,
            ascii: false,
            hex: false,
            link: false,
            snaplen: 65535,
            promisc: true,
            timeout_ms: 1000,
            scope: None,
            audit_log: PathBuf::from("audit.jsonl"),
        };
        assert!(args.validate().is_err());
    }

    #[test]
    fn accepts_offline_read() {
        let args = CaptureArgs {
            list_interfaces: false,
            interface: None,
            read: Some(PathBuf::from("a.pcap")),
            write: None,
            count: Some(10),
            filter: None,
            numeric: true,
            timestamp: 0,
            verbose: 1,
            stats: true,
            quiet: false,
            ascii: false,
            hex: false,
            link: false,
            snaplen: 65535,
            promisc: true,
            timeout_ms: 1000,
            scope: None,
            audit_log: PathBuf::from("audit.jsonl"),
        };
        assert!(args.validate().is_ok());
    }
}
