//! Metasploit-style module registry — authorized auxiliary modules only.

pub mod detect_cmd;
pub mod diff_cmd;
pub mod enum_svc;
pub mod export_cmd;
pub mod import_cmd;
pub mod report_cmd;
pub mod scan;
pub mod session_cmd;
pub mod watch_cmd;

/// Module risk / capability class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    /// Passive observation (pcap, decode, stats).
    Passive,
    /// Scoped active probing without exploit payloads.
    Auxiliary,
}

/// One registered module descriptor.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: &'static str,
    pub kind: RiskClass,
    pub summary: &'static str,
    pub requires_scope: bool,
}

/// Built-in modules. No exploit / payload modules are registered.
pub fn catalog() -> Vec<ModuleInfo> {
    vec![
        ModuleInfo {
            name: "capture",
            kind: RiskClass::Passive,
            summary: "tcpdump-class packet capture, BPF, PCAP, decode, stats",
            requires_scope: false,
        },
        ModuleInfo {
            name: "detect/ids_lite",
            kind: RiskClass::Passive,
            summary: "IDS-lite + YAML packs (expressions, correlation windows)",
            requires_scope: false,
        },
        ModuleInfo {
            name: "watch/dashboard",
            kind: RiskClass::Passive,
            summary: "Live terminal + optional localhost HTML/API dashboard over capture",
            requires_scope: false,
        },
        ModuleInfo {
            name: "scan/tcp_connect",
            kind: RiskClass::Auxiliary,
            summary: "Allowlisted TCP connect scan with rate limits and audit log",
            requires_scope: true,
        },
        ModuleInfo {
            name: "enum/banner_tls",
            kind: RiskClass::Auxiliary,
            summary: "Service banners + TLS certificate metadata (no session decryption)",
            requires_scope: true,
        },
        ModuleInfo {
            name: "export/siem",
            kind: RiskClass::Passive,
            summary: "Convert detect JSON to SIEM formats (jsonl / CEF / syslog)",
            requires_scope: false,
        },
        ModuleInfo {
            name: "import/suricata_eve",
            kind: RiskClass::Passive,
            summary: "Import Suricata EVE JSONL alerts into Devil Eye / SIEM",
            requires_scope: false,
        },
        ModuleInfo {
            name: "import/zeek_notice",
            kind: RiskClass::Passive,
            summary: "Import Zeek notice.log (TSV/JSONL) into Devil Eye / SIEM",
            requires_scope: false,
        },
        ModuleInfo {
            name: "import/zeek_weird",
            kind: RiskClass::Passive,
            summary: "Import Zeek weird.log (TSV/JSONL) into Devil Eye / SIEM",
            requires_scope: false,
        },
        ModuleInfo {
            name: "diff/alerts",
            kind: RiskClass::Passive,
            summary: "Compare two detect JSON alert reports (before/after)",
            requires_scope: false,
        },
        ModuleInfo {
            name: "session",
            kind: RiskClass::Passive,
            summary: "Multi-operator engagement sessions (scope-ticket authenticated)",
            requires_scope: true,
        },
        ModuleInfo {
            name: "report/evidence",
            kind: RiskClass::Passive,
            summary: "Evidence packs with templates (full/executive/compact)",
            requires_scope: false,
        },
    ]
}

/// Print module catalog to stdout.
pub fn print_catalog() {
    println!("Devil Eye modules (authorized use only)");
    println!("---------------------------------------");
    println!("This is NOT Metasploit: no exploit payloads, no credential theft, no malware.");
    println!();
    for m in catalog() {
        let risk = match m.kind {
            RiskClass::Passive => "passive",
            RiskClass::Auxiliary => "auxiliary",
        };
        let scope = if m.requires_scope {
            "scope REQUIRED"
        } else {
            "scope optional"
        };
        println!("  {:<22} [{risk}] ({scope})", m.name);
        println!("      {}", m.summary);
    }
}
