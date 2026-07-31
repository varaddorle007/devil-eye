//! Command-line interface — tcpdump capture + modular authorized assessment.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

/// Devil Eye — authorized cybersecurity toolkit.
#[derive(Debug, Parser)]
#[command(
    name = "devil-eye",
    version,
    about = "Authorized cybersecurity toolkit (capture + scoped assessment)",
    long_about = "Devil Eye combines tcpdump-class packet analysis with Metasploit-style \
modular assessment — but ONLY for networks you own or have written authorization to test.\n\n\
It does NOT ship exploit payloads, credential theft, malware, or unauthorized access tools.\n\
Active modules require a signed-off scope file and write an audit log."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Passive packet capture / PCAP replay (tcpdump-like)
    Capture(CaptureArgs),
    /// Authorized TCP connect scan (requires --scope)
    Scan(ScanArgs),
    /// Authorized service banner + TLS cert metadata (requires --scope)
    Enum(EnumArgs),
    /// IDS-lite detection over live capture or PCAP
    Detect(DetectArgs),
    /// Live terminal / HTML dashboard over capture + IDS-lite
    Watch(WatchArgs),
    /// Convert detect JSON alerts to SIEM formats (jsonl/CEF/syslog)
    Export(ExportArgs),
    /// Import Suricata EVE or Zeek notice/weird logs into Devil Eye alerts
    Import(ImportArgs),
    /// Compare two detect-compatible alert JSON reports
    Diff(DiffArgs),
    /// Multi-operator engagement session (create/join/notes)
    Session(SessionArgs),
    /// Assemble Markdown/HTML/JSON engagement evidence pack
    Report(ReportArgs),
    /// List built-in modules and their risk class
    Modules,
}

/// tcpdump-inspired capture flags.
#[derive(Debug, Parser, Clone)]
pub struct CaptureArgs {
    /// List capture interfaces and exit
    #[arg(short = 'D', long = "list-interfaces")]
    pub list_interfaces: bool,

    /// Capture interface name (live mode)
    #[arg(short = 'i', long = "interface")]
    pub interface: Option<String>,

    /// Read packets from a classical PCAP or PCAPNG file
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Option<PathBuf>,

    /// Write packets to a classical PCAP file
    #[arg(short = 'w', long = "write", value_name = "FILE")]
    pub write: Option<PathBuf>,

    /// Exit after receiving count packets
    #[arg(short = 'c', long = "count")]
    pub count: Option<u64>,

    /// Packet filter (tcpdump-like subset offline; full BPF on live with `--features live`)
    #[arg(short = 'f', long = "filter", value_name = "EXPR")]
    pub filter: Option<String>,

    /// Don't convert addresses / ports to names
    #[arg(short = 'n', long = "numeric")]
    pub numeric: bool,

    /// Increase verbosity (-v, -vv)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Print periodic and final traffic statistics
    #[arg(long = "stats")]
    pub stats: bool,

    /// Suppress per-packet lines (useful with --stats)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Print each packet in ASCII (non-printable → `.`), like tcpdump -A
    #[arg(short = 'A', long = "ascii")]
    pub ascii: bool,

    /// Print hex + ASCII dump of each packet, like tcpdump -X
    #[arg(short = 'X', long = "hex")]
    pub hex: bool,

    /// Print link-level (Ethernet) header on each packet line, like tcpdump -e
    #[arg(short = 'e', long = "link")]
    pub link: bool,

    /// Snapshot length (bytes captured per packet)
    #[arg(short = 's', long = "snaplen", default_value_t = 65535)]
    pub snaplen: i32,

    /// Enable promiscuous mode for live capture (default: true)
    #[arg(long = "promisc", default_value_t = true)]
    pub promisc: bool,

    /// Read timeout for live capture in milliseconds
    #[arg(long = "timeout-ms", default_value_t = 1000)]
    pub timeout_ms: i32,

    /// Optional scope file (logged for governance; not required for passive capture)
    #[arg(long = "scope", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

/// Authorized connect-scan flags (Metasploit-style auxiliary module).
#[derive(Debug, Parser, Clone)]
pub struct ScanArgs {
    /// Mandatory authorization scope file (JSON)
    #[arg(long = "scope", value_name = "FILE", required = true)]
    pub scope: PathBuf,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,

    /// Optional JSON report output
    #[arg(long = "json-out", value_name = "FILE")]
    pub json_out: Option<PathBuf>,

    /// Increase verbosity
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Authorized service enumeration flags (banners + TLS cert metadata).
#[derive(Debug, Parser, Clone)]
pub struct EnumArgs {
    /// Mandatory authorization scope file (JSON)
    #[arg(long = "scope", value_name = "FILE", required = true)]
    pub scope: PathBuf,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,

    /// Optional JSON report output
    #[arg(long = "json-out", value_name = "FILE")]
    pub json_out: Option<PathBuf>,

    /// Extra ports to treat as TLS (comma-separated). Defaults include 443,8443.
    #[arg(long = "tls-ports", value_name = "PORTS")]
    pub tls_ports: Option<String>,

    /// Increase verbosity
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// IDS-lite detection over a capture source.
#[derive(Debug, Parser, Clone)]
pub struct DetectArgs {
    /// Capture interface name (live mode)
    #[arg(short = 'i', long = "interface")]
    pub interface: Option<String>,

    /// Read packets from a classical PCAP or PCAPNG file
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Option<PathBuf>,

    /// Packet filter (tcpdump-like subset offline; full BPF on live with `--features live`)
    #[arg(short = 'f', long = "filter", value_name = "EXPR")]
    pub filter: Option<String>,

    /// Exit after processing count packets
    #[arg(short = 'c', long = "count")]
    pub count: Option<u64>,

    /// Snapshot length
    #[arg(short = 's', long = "snaplen", default_value_t = 65535)]
    pub snaplen: i32,

    /// Promiscuous mode for live capture
    #[arg(long = "promisc", default_value_t = true)]
    pub promisc: bool,

    /// Live read timeout ms
    #[arg(long = "timeout-ms", default_value_t = 1000)]
    pub timeout_ms: i32,

    /// Optional scope file (governance / audit identity)
    #[arg(long = "scope", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,

    /// Optional JSON alert report
    #[arg(long = "json-out", value_name = "FILE")]
    pub json_out: Option<PathBuf>,

    /// YAML rule pack (thresholds / rare ports / disabled rules)
    #[arg(long = "rules", value_name = "FILE")]
    pub rules: Option<PathBuf>,

    /// SYN scan threshold (distinct destination ports)
    #[arg(long = "syn-scan-ports")]
    pub syn_scan_ports: Option<usize>,

    /// Host sweep threshold (distinct destination hosts via SYN)
    #[arg(long = "host-sweep-hosts")]
    pub host_sweep_hosts: Option<usize>,

    /// ICMP echo-request flood threshold (per source, within window)
    #[arg(long = "icmp-echo-count")]
    pub icmp_echo_count: Option<usize>,

    /// DNS unique-name volume threshold
    #[arg(long = "dns-unique-names")]
    pub dns_unique_names: Option<usize>,

    /// TCP RST burst threshold
    #[arg(long = "tcp-rst-count")]
    pub tcp_rst_count: Option<usize>,

    /// DHCP discover flood threshold
    #[arg(long = "dhcp-discover-count")]
    pub dhcp_discover_count: Option<usize>,

    /// DNS NXDOMAIN burst threshold
    #[arg(long = "dns-nxdomain-count")]
    pub dns_nxdomain_count: Option<usize>,

    /// Stream alerts to a SIEM file (jsonl / cef / syslog lines)
    #[arg(long = "siem-out", value_name = "FILE")]
    pub siem_out: Option<PathBuf>,

    /// SIEM line format: jsonl (default), cef, syslog
    #[arg(long = "siem-format", value_name = "FMT", default_value = "jsonl")]
    pub siem_format: String,

    /// Optional UDP destination for SIEM lines (host:port)
    #[arg(long = "siem-udp", value_name = "ADDR")]
    pub siem_udp: Option<String>,

    /// Attach to a multi-operator session directory (requires --scope)
    #[arg(long = "session-dir", value_name = "DIR")]
    pub session_dir: Option<PathBuf>,

    /// Role when auto-joining a session (operator|observer)
    #[arg(long = "session-role", default_value = "operator")]
    pub session_role: String,
}

impl DetectArgs {
    /// Map into capture args for the shared capture backend.
    pub fn to_capture_args(&self) -> CaptureArgs {
        CaptureArgs {
            list_interfaces: false,
            interface: self.interface.clone(),
            read: self.read.clone(),
            write: None,
            count: self.count,
            filter: self.filter.clone(),
            numeric: true,
            verbose: 0,
            stats: false,
            quiet: true,
            ascii: false,
            hex: false,
            link: false,
            snaplen: self.snaplen,
            promisc: self.promisc,
            timeout_ms: self.timeout_ms,
            scope: self.scope.clone(),
            audit_log: self.audit_log.clone(),
        }
    }
}

/// Live dashboard over a capture source (terminal + optional HTML/HTTP).
#[derive(Debug, Parser, Clone)]
pub struct WatchArgs {
    #[command(flatten)]
    pub base: DetectArgs,

    /// Dashboard refresh interval in milliseconds
    #[arg(long = "refresh-ms", default_value_t = 500)]
    pub refresh_ms: u64,

    /// Write/refresh a self-contained HTML snapshot file
    #[arg(long = "html-out", value_name = "FILE")]
    pub html_out: Option<PathBuf>,

    /// Serve live HTML + JSON API on host:port (e.g. 127.0.0.1:8787)
    #[arg(long = "serve", value_name = "ADDR")]
    pub serve: Option<String>,

    /// How many recent alerts to keep on the dashboard
    #[arg(long = "recent", default_value_t = 12)]
    pub recent: usize,

    /// Do not clear the terminal between redraws (CI / logs)
    #[arg(long = "no-clear")]
    pub no_clear: bool,

    /// Suppress terminal dashboard output
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// After PCAP EOF, exit immediately even if --serve is set
    #[arg(long = "no-hold")]
    pub no_hold: bool,
}

impl std::ops::Deref for WatchArgs {
    type Target = DetectArgs;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl WatchArgs {
    /// Map into capture args for the shared capture backend.
    pub fn to_capture_args(&self) -> CaptureArgs {
        self.base.to_capture_args()
    }
}

/// Offline conversion of detect JSON into SIEM formats.
#[derive(Debug, Parser, Clone)]
pub struct ExportArgs {
    /// Detect module JSON report (`detect --json-out`)
    #[arg(long = "detect-json", value_name = "FILE", required = true)]
    pub detect_json: PathBuf,

    /// Write SIEM lines to this file
    #[arg(long = "siem-out", value_name = "FILE")]
    pub siem_out: Option<PathBuf>,

    /// SIEM line format: jsonl (default), cef, syslog
    #[arg(long = "siem-format", value_name = "FMT", default_value = "jsonl")]
    pub siem_format: String,

    /// Optional UDP destination (host:port)
    #[arg(long = "siem-udp", value_name = "ADDR")]
    pub siem_udp: Option<String>,

    /// Optional scope file (ticket/operator stamped on events)
    #[arg(long = "scope", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

/// Import Suricata EVE JSONL or Zeek notice/weird logs into detect-compatible alerts.
#[derive(Debug, Parser, Clone)]
pub struct ImportArgs {
    /// Suricata eve.json / eve.jsonl path
    #[arg(
        long = "eve",
        value_name = "FILE",
        conflicts_with_all = ["zeek", "zeek_weird"]
    )]
    pub eve: Option<PathBuf>,

    /// Zeek notice.log path — TSV (`#fields`) or JSONL
    #[arg(
        long = "zeek",
        value_name = "FILE",
        conflicts_with_all = ["eve", "zeek_weird"]
    )]
    pub zeek: Option<PathBuf>,

    /// Zeek weird.log path — TSV (`#fields`) or JSONL
    #[arg(
        long = "zeek-weird",
        value_name = "FILE",
        conflicts_with_all = ["eve", "zeek"]
    )]
    pub zeek_weird: Option<PathBuf>,

    /// Write Devil Eye detect-compatible JSON (usable with `report --detect-json`)
    #[arg(long = "json-out", value_name = "FILE")]
    pub json_out: Option<PathBuf>,

    /// Suricata event types to keep (comma-separated). Default: alert
    #[arg(long = "event-types", value_name = "LIST", default_value = "alert")]
    pub event_types: String,

    /// Zeek notice `note` types to keep (comma-separated). Empty = all
    #[arg(long = "note-types", value_name = "LIST", default_value = "")]
    pub note_types: String,

    /// Zeek weird `name` values to keep (comma-separated). Empty = all
    #[arg(long = "weird-names", value_name = "LIST", default_value = "")]
    pub weird_names: String,

    /// Maximum alerts to keep (default 100000)
    #[arg(long = "max-alerts", default_value_t = 100_000)]
    pub max_alerts: usize,

    /// Stream converted alerts to a SIEM file
    #[arg(long = "siem-out", value_name = "FILE")]
    pub siem_out: Option<PathBuf>,

    /// SIEM line format: jsonl (default), cef, syslog
    #[arg(long = "siem-format", value_name = "FMT", default_value = "jsonl")]
    pub siem_format: String,

    /// Optional UDP destination for SIEM lines (host:port)
    #[arg(long = "siem-udp", value_name = "ADDR")]
    pub siem_udp: Option<String>,

    /// Optional scope file (ticket/operator stamp)
    #[arg(long = "scope", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,

    /// Print first alerts to stdout
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Compare two detect-compatible alert JSON reports (before vs after).
#[derive(Debug, Parser, Clone)]
pub struct DiffArgs {
    /// Baseline / earlier detect JSON (`detect --json-out`, import, …)
    #[arg(long = "before", value_name = "FILE", required = true)]
    pub before: PathBuf,

    /// Newer detect JSON to compare against `--before`
    #[arg(long = "after", value_name = "FILE", required = true)]
    pub after: PathBuf,

    /// Fingerprint mode: full (rule|src|detail), rule-src, or rule
    #[arg(long = "key", value_name = "MODE", default_value = "full")]
    pub key: String,

    /// Write structured diff JSON
    #[arg(long = "json-out", value_name = "FILE")]
    pub json_out: Option<PathBuf>,

    /// Exit non-zero when any alerts are gone or new
    #[arg(long = "fail-on-diff")]
    pub fail_on_diff: bool,

    /// Optional scope file (ticket/operator stamped in audit)
    #[arg(long = "scope", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Append-only audit log path (JSONL)
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

/// Multi-operator engagement session commands.
#[derive(Debug, Parser, Clone)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Debug, Subcommand, Clone)]
pub enum SessionCommand {
    /// Create a new shared session directory (lead = scope.operator)
    Create(SessionCreateArgs),
    /// Join / re-join a session with your scope identity
    Join(SessionJoinArgs),
    /// Refresh presence heartbeat
    Heartbeat(SessionScopeDirArgs),
    /// Mark yourself as left
    Leave(SessionScopeDirArgs),
    /// Show operators + shared note/alert counts
    Status(SessionDirArgs),
    /// Append a free-form operator note
    Note(SessionNoteArgs),
}

#[derive(Debug, Parser, Clone)]
pub struct SessionCreateArgs {
    /// Authorization scope (ticket + operator)
    #[arg(long = "scope", value_name = "FILE", required = true)]
    pub scope: PathBuf,
    /// Session directory to create
    #[arg(long = "session-dir", value_name = "DIR", required = true)]
    pub session_dir: PathBuf,
    /// Optional human title
    #[arg(long = "title", default_value = "")]
    pub title: String,
    /// Max concurrent operators
    #[arg(long = "max-operators", default_value_t = 16)]
    pub max_operators: usize,
    /// Optional comma-separated operator allowlist
    #[arg(long = "allow", value_name = "NAMES")]
    pub allow: Option<String>,
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

#[derive(Debug, Parser, Clone)]
pub struct SessionJoinArgs {
    #[arg(long = "scope", value_name = "FILE", required = true)]
    pub scope: PathBuf,
    #[arg(long = "session-dir", value_name = "DIR", required = true)]
    pub session_dir: PathBuf,
    /// Role: lead | operator | observer (default operator)
    #[arg(long = "role", default_value = "operator")]
    pub role: String,
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

#[derive(Debug, Parser, Clone)]
pub struct SessionScopeDirArgs {
    #[arg(long = "scope", value_name = "FILE", required = true)]
    pub scope: PathBuf,
    #[arg(long = "session-dir", value_name = "DIR", required = true)]
    pub session_dir: PathBuf,
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

#[derive(Debug, Parser, Clone)]
pub struct SessionDirArgs {
    #[arg(long = "session-dir", value_name = "DIR", required = true)]
    pub session_dir: PathBuf,
}

#[derive(Debug, Parser, Clone)]
pub struct SessionNoteArgs {
    #[arg(long = "scope", value_name = "FILE", required = true)]
    pub scope: PathBuf,
    #[arg(long = "session-dir", value_name = "DIR", required = true)]
    pub session_dir: PathBuf,
    #[arg(long = "text", value_name = "NOTE", required = true)]
    pub text: String,
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

/// Assemble an engagement evidence pack from prior outputs.
#[derive(Debug, Parser, Clone)]
pub struct ReportArgs {
    /// Optional authorization scope file (fills ticket/operator/targets)
    #[arg(long = "scope", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Scan module JSON report (`scan --json-out`)
    #[arg(long = "scan-json", value_name = "FILE")]
    pub scan_json: Option<PathBuf>,

    /// Enum module JSON report (`enum --json-out`)
    #[arg(long = "enum-json", value_name = "FILE")]
    pub enum_json: Option<PathBuf>,

    /// Detect module JSON report (`detect --json-out`)
    #[arg(long = "detect-json", value_name = "FILE")]
    pub detect_json: Option<PathBuf>,

    /// Optional PCAP to summarize into the report
    #[arg(long = "pcap", value_name = "FILE")]
    pub pcap: Option<PathBuf>,

    /// Number of PCAP packet-timeline buckets (1–128, default 24)
    #[arg(long = "pcap-timeline-buckets", value_name = "N")]
    pub pcap_timeline_buckets: Option<usize>,

    /// Optional audit JSONL to include as a trail
    #[arg(long = "audit-in", value_name = "FILE")]
    pub audit_in: Option<PathBuf>,

    /// Free-form notes (repeatable)
    #[arg(long = "note", value_name = "TEXT")]
    pub notes: Vec<String>,

    /// Report layout template: full | executive | compact
    #[arg(long = "template", value_name = "NAME", default_value = "full")]
    pub template: String,

    /// Write Markdown report
    #[arg(long = "out-md", value_name = "FILE")]
    pub out_md: Option<PathBuf>,

    /// Write HTML report
    #[arg(long = "out-html", value_name = "FILE")]
    pub out_html: Option<PathBuf>,

    /// Write JSON report
    #[arg(long = "out-json", value_name = "FILE")]
    pub out_json: Option<PathBuf>,

    /// Append-only audit log for this report run
    #[arg(
        long = "audit-log",
        value_name = "FILE",
        default_value = "devil-eye-audit.jsonl"
    )]
    pub audit_log: PathBuf,
}

impl CaptureArgs {
    /// Validate mutually exclusive / required modes.
    pub fn validate(&self) -> Result<()> {
        if self.list_interfaces {
            if self.interface.is_some()
                || self.read.is_some()
                || self.write.is_some()
                || self.filter.is_some()
                || self.count.is_some()
            {
                bail!("-D/--list-interfaces cannot be combined with capture options");
            }
            return Ok(());
        }

        match (&self.interface, &self.read) {
            (Some(_), Some(_)) => bail!("use either -i/--interface or -r/--read, not both"),
            (None, None) => bail!("specify -i/--interface, -r/--read, or -D/--list-interfaces"),
            _ => {}
        }

        if let Some(c) = self.count {
            if c == 0 {
                bail!("-c/--count must be greater than zero");
            }
        }

        if self.snaplen <= 0 {
            bail!("-s/--snaplen must be positive");
        }

        if self.timeout_ms < 0 {
            bail!("--timeout-ms must be non-negative");
        }

        Ok(())
    }
}

/// Backward-compatible alias used by capture pipeline / tests.
pub type Args = CaptureArgs;
