//! IDS-lite detection engine (bounded, stateful, authorized observation).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::expr::{field_display, CorrDetail, CustomRule, OnceMode};
use crate::packet::{AppInfo, DecodedPacket, TcpFlags, TransportInfo};

const MAX_SOURCES: usize = 512;
const MAX_PORTS_PER_SRC: usize = 256;
const MAX_HOSTS_PER_SRC: usize = 256;
const MAX_DNS_NAMES_PER_SRC: usize = 256;
const MAX_CORR_BUCKETS: usize = 2048;
const MAX_CORR_UNIQUES: usize = 256;
const MAX_COOLDOWN_KEYS: usize = 4096;

/// Tunable detection thresholds.
#[derive(Debug, Clone)]
pub struct DetectConfig {
    /// Distinct destination ports contacted with SYN in the window.
    pub syn_scan_ports: usize,
    /// Distinct destination hosts contacted with SYN in the window.
    pub host_sweep_hosts: usize,
    /// Sliding window for scan / sweep / ICMP aggregation.
    pub scan_window: Duration,
    /// Destination ports treated as "rare" when contacted.
    pub rare_ports: HashSet<u16>,
    /// Unique DNS QNAMEs per source before alerting.
    pub dns_unique_names: usize,
    /// QNAME length that hints at tunneling.
    pub dns_long_name: usize,
    /// ICMP echo requests from one source within the window.
    pub icmp_echo_count: usize,
    /// TCP RST packets from one source within the window.
    pub tcp_rst_count: usize,
    /// DHCP discovers from one client within the window.
    pub dhcp_discover_count: usize,
    /// NXDOMAIN DNS responses toward one client within the window.
    pub dns_nxdomain_count: usize,
    /// Lowercase rule ids that should not emit alerts.
    pub disabled_rules: HashSet<String>,
    /// Compiled custom expression rules from a YAML pack.
    pub custom_rules: Vec<CustomRule>,
    /// Suppress repeat alerts for the same `(rule, src)` within this many ms (0 = off).
    pub alert_cooldown_ms: u64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        let mut rare_ports = HashSet::new();
        for p in [
            4444, 5555, 6666, 31337, 12345, 1337, 4443, 8888, 9999, 65000,
        ] {
            rare_ports.insert(p);
        }
        Self {
            syn_scan_ports: 15,
            host_sweep_hosts: 20,
            scan_window: Duration::from_secs(30),
            rare_ports,
            dns_unique_names: 40,
            dns_long_name: 60,
            icmp_echo_count: 50,
            tcp_rst_count: 40,
            dhcp_discover_count: 20,
            dns_nxdomain_count: 30,
            disabled_rules: HashSet::new(),
            custom_rules: Vec::new(),
            alert_cooldown_ms: 0,
        }
    }
}

impl DetectConfig {
    /// Whether a named rule is allowed to fire.
    pub fn rule_enabled(&self, rule: &str) -> bool {
        !self.disabled_rules.contains(&rule.to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub ts_unix_ms: u64,
    pub rule: String,
    pub severity: String,
    pub src: String,
    pub detail: String,
}

#[derive(Debug, Default)]
struct SrcScanState {
    first: Option<Instant>,
    ports: HashSet<u16>,
    alerted: bool,
}

#[derive(Debug, Default)]
struct SrcHostSweepState {
    first: Option<Instant>,
    hosts: HashSet<IpAddr>,
    alerted: bool,
}

#[derive(Debug, Default)]
struct SrcDnsState {
    names: HashSet<String>,
    alerted_volume: bool,
}

#[derive(Debug, Default)]
struct SrcIcmpState {
    first: Option<Instant>,
    count: usize,
    alerted: bool,
}

#[derive(Debug, Default)]
struct SrcRstState {
    first: Option<Instant>,
    count: usize,
    alerted: bool,
}

#[derive(Debug, Default)]
struct DhcpFloodState {
    first: Option<Instant>,
    count: usize,
    alerted: bool,
}

#[derive(Debug, Default)]
struct NxDomainState {
    first: Option<Instant>,
    count: usize,
    alerted: bool,
}

/// Classify classic stealth TCP probe flag combinations.
fn stealth_rule(flags: &TcpFlags) -> Option<&'static str> {
    let no_syn_ack_rst = !flags.syn && !flags.ack && !flags.rst;
    if no_syn_ack_rst && !flags.fin && !flags.psh && !flags.urg {
        return Some("tcp_null_scan");
    }
    if no_syn_ack_rst && flags.fin && flags.psh && flags.urg {
        return Some("tcp_xmas_scan");
    }
    if no_syn_ack_rst && flags.fin && !flags.psh && !flags.urg {
        return Some("tcp_fin_scan");
    }
    None
}

fn is_icmp_echo_request(version: u8, type_u8: u8) -> bool {
    match version {
        4 => type_u8 == 8,
        6 => type_u8 == 128,
        _ => false,
    }
}

#[derive(Debug, Default)]
struct CustomCorrBucket {
    first_ms: u64,
    count: usize,
    uniques: HashSet<String>,
}

/// Stateful detector over a packet stream.
#[derive(Debug)]
pub struct Detector {
    cfg: DetectConfig,
    scans: HashMap<IpAddr, SrcScanState>,
    sweeps: HashMap<IpAddr, SrcHostSweepState>,
    dns: HashMap<IpAddr, SrcDnsState>,
    icmp: HashMap<IpAddr, SrcIcmpState>,
    rst: HashMap<IpAddr, SrcRstState>,
    dhcp: HashMap<String, DhcpFloodState>,
    nxdomain: HashMap<IpAddr, NxDomainState>,
    /// IP -> first-seen MAC for ARP conflict detection.
    arp_ip_mac: HashMap<String, String>,
    rare_alerted: HashSet<(IpAddr, u16)>,
    stealth_alerted: HashSet<(IpAddr, String)>,
    http_auth_alerted: HashSet<IpAddr>,
    tls_legacy_alerted: HashSet<IpAddr>,
    arp_conflict_alerted: HashSet<String>,
    custom_once: HashSet<String>,
    custom_per_src: HashSet<(String, String)>,
    /// (rule_id, track_key) -> sliding window state for correlated custom rules.
    custom_corr: HashMap<(String, String), CustomCorrBucket>,
    /// Last emit time for `(rule, src)` cooldown keys.
    cooldown_last: HashMap<(String, String), u64>,
    /// Alerts dropped by cooldown.
    suppressed: u64,
    alerts: Vec<Alert>,
}

impl Detector {
    pub fn new(cfg: DetectConfig) -> Self {
        Self {
            cfg,
            scans: HashMap::new(),
            sweeps: HashMap::new(),
            dns: HashMap::new(),
            icmp: HashMap::new(),
            rst: HashMap::new(),
            dhcp: HashMap::new(),
            nxdomain: HashMap::new(),
            arp_ip_mac: HashMap::new(),
            rare_alerted: HashSet::new(),
            stealth_alerted: HashSet::new(),
            http_auth_alerted: HashSet::new(),
            tls_legacy_alerted: HashSet::new(),
            arp_conflict_alerted: HashSet::new(),
            custom_once: HashSet::new(),
            custom_per_src: HashSet::new(),
            custom_corr: HashMap::new(),
            cooldown_last: HashMap::new(),
            suppressed: 0,
            alerts: Vec::new(),
        }
    }

    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    /// Count of alerts suppressed by `--alert-cooldown-ms` / pack setting.
    pub fn suppressed(&self) -> u64 {
        self.suppressed
    }

    /// Ingest one decoded packet. Returns new alerts raised for this packet.
    pub fn observe(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) -> Vec<Alert> {
        let before = self.alerts.len();
        self.observe_scan(decoded, ts_unix_ms);
        self.observe_host_sweep(decoded, ts_unix_ms);
        self.observe_stealth(decoded, ts_unix_ms);
        self.observe_rare(decoded, ts_unix_ms);
        self.observe_dns(decoded, ts_unix_ms);
        self.observe_icmp(decoded, ts_unix_ms);
        self.observe_rst_burst(decoded, ts_unix_ms);
        self.observe_arp(decoded, ts_unix_ms);
        self.observe_http_auth(decoded, ts_unix_ms);
        self.observe_tls_legacy(decoded, ts_unix_ms);
        self.observe_dhcp_flood(decoded, ts_unix_ms);
        self.observe_nxdomain(decoded, ts_unix_ms);
        self.observe_custom(decoded, ts_unix_ms);
        self.alerts[before..].to_vec()
    }

    fn observe_scan(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(TransportInfo::Tcp(tcp))) = (&decoded.ip, &decoded.transport) else {
            return;
        };
        // SYN without ACK ≈ scan probe / half-open.
        if !tcp.flags.syn || tcp.flags.ack {
            return;
        }

        if self.scans.len() >= MAX_SOURCES && !self.scans.contains_key(&ip.src) {
            return;
        }

        let should_alert;
        let port_count;
        let window = self.cfg.scan_window;
        let src = ip.src.to_string();
        {
            let now = Instant::now();
            let state = self.scans.entry(ip.src).or_default();
            if let Some(first) = state.first {
                if now.duration_since(first) > window {
                    state.first = Some(now);
                    state.ports.clear();
                    state.alerted = false;
                }
            } else {
                state.first = Some(now);
            }

            if state.ports.len() < MAX_PORTS_PER_SRC {
                state.ports.insert(tcp.dst_port);
            }

            should_alert = !state.alerted && state.ports.len() >= self.cfg.syn_scan_ports;
            port_count = state.ports.len();
            if should_alert {
                state.alerted = true;
            }
        }

        if should_alert {
            self.push(
                ts_unix_ms,
                "tcp_syn_scan",
                "high",
                &src,
                &format!("SYN to {port_count} distinct destination ports within {window:?}"),
            );
        }
    }

    fn observe_host_sweep(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(TransportInfo::Tcp(tcp))) = (&decoded.ip, &decoded.transport) else {
            return;
        };
        if !tcp.flags.syn || tcp.flags.ack {
            return;
        }

        if self.sweeps.len() >= MAX_SOURCES && !self.sweeps.contains_key(&ip.src) {
            return;
        }

        let should_alert;
        let host_count;
        let window = self.cfg.scan_window;
        let src = ip.src.to_string();
        {
            let now = Instant::now();
            let state = self.sweeps.entry(ip.src).or_default();
            if let Some(first) = state.first {
                if now.duration_since(first) > window {
                    state.first = Some(now);
                    state.hosts.clear();
                    state.alerted = false;
                }
            } else {
                state.first = Some(now);
            }

            if state.hosts.len() < MAX_HOSTS_PER_SRC {
                state.hosts.insert(ip.dst);
            }

            should_alert = !state.alerted && state.hosts.len() >= self.cfg.host_sweep_hosts;
            host_count = state.hosts.len();
            if should_alert {
                state.alerted = true;
            }
        }

        if should_alert {
            self.push(
                ts_unix_ms,
                "tcp_host_sweep",
                "high",
                &src,
                &format!("SYN to {host_count} distinct hosts within {window:?}"),
            );
        }
    }

    fn observe_stealth(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(TransportInfo::Tcp(tcp))) = (&decoded.ip, &decoded.transport) else {
            return;
        };
        let Some(rule) = stealth_rule(&tcp.flags) else {
            return;
        };

        let key = (ip.src, rule.to_string());
        if self.stealth_alerted.contains(&key) {
            return;
        }
        if self.stealth_alerted.len() >= MAX_SOURCES * 4 {
            return;
        }
        self.stealth_alerted.insert(key);

        self.push(
            ts_unix_ms,
            rule,
            "high",
            &ip.src.to_string(),
            &format!(
                "stealth TCP flags [{}] toward {}:{}",
                tcp.flags.label(),
                ip.dst,
                tcp.dst_port
            ),
        );
    }

    fn observe_rare(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let Some(ip) = &decoded.ip else {
            return;
        };
        let dst_port = match &decoded.transport {
            Some(TransportInfo::Tcp(t)) => {
                if t.flags.syn && !t.flags.ack {
                    t.dst_port
                } else {
                    return;
                }
            }
            Some(TransportInfo::Udp(u)) => u.dst_port,
            _ => return,
        };

        if !self.cfg.rare_ports.contains(&dst_port) {
            return;
        }
        let key = (ip.src, dst_port);
        if self.rare_alerted.contains(&key) {
            return;
        }
        if self.rare_alerted.len() >= MAX_SOURCES * 4 {
            return;
        }
        self.rare_alerted.insert(key);
        self.push(
            ts_unix_ms,
            "rare_port",
            "medium",
            &ip.src.to_string(),
            &format!("traffic toward uncommon port {} (dst {})", dst_port, ip.dst),
        );
    }

    fn observe_dns(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(AppInfo::Dns(dns))) = (&decoded.ip, &decoded.app) else {
            return;
        };
        if !dns.is_query {
            return;
        }

        if self.dns.len() >= MAX_SOURCES && !self.dns.contains_key(&ip.src) {
            return;
        }

        let src = ip.src.to_string();
        let long_threshold = self.cfg.dns_long_name;
        let volume_threshold = self.cfg.dns_unique_names;

        let mut long_alerts: Vec<String> = Vec::new();
        let volume_alert;
        {
            let state = self.dns.entry(ip.src).or_default();
            for q in &dns.questions {
                let name = q.split_whitespace().next().unwrap_or(q).to_string();
                if name.len() >= long_threshold {
                    long_alerts.push(format!("long DNS QNAME len={} ({name})", name.len()));
                }
                if state.names.len() < MAX_DNS_NAMES_PER_SRC {
                    state.names.insert(name);
                }
            }

            volume_alert = if !state.alerted_volume && state.names.len() >= volume_threshold {
                state.alerted_volume = true;
                Some(format!(
                    "{} unique DNS query names observed (possible enumeration/tunneling)",
                    state.names.len()
                ))
            } else {
                None
            };
        }

        for detail in long_alerts {
            self.push(ts_unix_ms, "dns_long_name", "medium", &src, &detail);
        }
        if let Some(detail) = volume_alert {
            self.push(ts_unix_ms, "dns_query_volume", "high", &src, &detail);
        }
    }

    fn observe_icmp(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(TransportInfo::Icmp(icmp))) = (&decoded.ip, &decoded.transport) else {
            return;
        };
        if !is_icmp_echo_request(icmp.version, icmp.type_u8) {
            return;
        }

        if self.icmp.len() >= MAX_SOURCES && !self.icmp.contains_key(&ip.src) {
            return;
        }

        let should_alert;
        let count;
        let window = self.cfg.scan_window;
        let src = ip.src.to_string();
        {
            let now = Instant::now();
            let state = self.icmp.entry(ip.src).or_default();
            if let Some(first) = state.first {
                if now.duration_since(first) > window {
                    state.first = Some(now);
                    state.count = 0;
                    state.alerted = false;
                }
            } else {
                state.first = Some(now);
            }

            state.count = state.count.saturating_add(1);
            should_alert = !state.alerted && state.count >= self.cfg.icmp_echo_count;
            count = state.count;
            if should_alert {
                state.alerted = true;
            }
        }

        if should_alert {
            self.push(
                ts_unix_ms,
                "icmp_echo_flood",
                "medium",
                &src,
                &format!("{count} ICMP echo requests within {window:?}"),
            );
        }
    }

    fn observe_rst_burst(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(TransportInfo::Tcp(tcp))) = (&decoded.ip, &decoded.transport) else {
            return;
        };
        if !tcp.flags.rst {
            return;
        }
        if self.rst.len() >= MAX_SOURCES && !self.rst.contains_key(&ip.src) {
            return;
        }

        let should_alert;
        let count;
        let window = self.cfg.scan_window;
        let src = ip.src.to_string();
        {
            let now = Instant::now();
            let state = self.rst.entry(ip.src).or_default();
            if let Some(first) = state.first {
                if now.duration_since(first) > window {
                    state.first = Some(now);
                    state.count = 0;
                    state.alerted = false;
                }
            } else {
                state.first = Some(now);
            }
            state.count = state.count.saturating_add(1);
            should_alert = !state.alerted && state.count >= self.cfg.tcp_rst_count;
            count = state.count;
            if should_alert {
                state.alerted = true;
            }
        }
        if should_alert {
            self.push(
                ts_unix_ms,
                "tcp_rst_burst",
                "medium",
                &src,
                &format!("{count} TCP RST packets within {window:?}"),
            );
        }
    }

    fn observe_arp(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let Some(AppInfo::Arp(arp)) = &decoded.app else {
            return;
        };
        if arp.sender_ip == "0.0.0.0" || arp.sender_mac == "00:00:00:00:00:00" {
            return;
        }
        let ip = arp.sender_ip.clone();
        let mac = arp.sender_mac.clone();
        let prev = self.arp_ip_mac.get(&ip).cloned();
        match prev {
            None => {
                if self.arp_ip_mac.len() < MAX_SOURCES {
                    self.arp_ip_mac.insert(ip, mac);
                }
            }
            Some(old) if old != mac => {
                if self.arp_conflict_alerted.contains(&ip) {
                    return;
                }
                if self.arp_conflict_alerted.len() >= MAX_SOURCES {
                    return;
                }
                self.arp_conflict_alerted.insert(ip.clone());
                self.push(
                    ts_unix_ms,
                    "arp_mac_conflict",
                    "high",
                    &mac,
                    &format!("IP {ip} claimed by MAC {mac} (previously {old})"),
                );
            }
            Some(_) => {}
        }
    }

    fn observe_http_auth(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(AppInfo::Http(http))) = (&decoded.ip, &decoded.app) else {
            return;
        };
        if !http.has_authorization {
            return;
        }
        if self.http_auth_alerted.contains(&ip.src) {
            return;
        }
        if self.http_auth_alerted.len() >= MAX_SOURCES {
            return;
        }
        self.http_auth_alerted.insert(ip.src);
        let host = http.host.as_deref().unwrap_or("-");
        self.push(
            ts_unix_ms,
            "http_cleartext_auth",
            "high",
            &ip.src.to_string(),
            &format!(
                "plaintext HTTP Authorization header toward {} ({})",
                ip.dst, host
            ),
        );
    }

    fn observe_tls_legacy(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(AppInfo::Tls(tls))) = (&decoded.ip, &decoded.app) else {
            return;
        };
        let legacy = matches!(tls.version.as_str(), "SSL3" | "TLS1.0" | "TLS1.1");
        if !legacy {
            return;
        }
        if self.tls_legacy_alerted.contains(&ip.src) {
            return;
        }
        if self.tls_legacy_alerted.len() >= MAX_SOURCES {
            return;
        }
        self.tls_legacy_alerted.insert(ip.src);
        let sni = tls.sni.as_deref().unwrap_or("-");
        let ja3 = tls.ja3_hash.as_deref().unwrap_or("-");
        self.push(
            ts_unix_ms,
            "tls_legacy_version",
            "medium",
            &ip.src.to_string(),
            &format!(
                "{} {} toward {} (sni={sni} ja3={ja3})",
                tls.handshake, tls.version, ip.dst
            ),
        );
    }

    fn observe_dhcp_flood(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let Some(AppInfo::Dhcp(dhcp)) = &decoded.app else {
            return;
        };
        if dhcp.message_type != "discover" {
            return;
        }
        let key = if dhcp.client_mac.is_empty() {
            decoded
                .ip
                .as_ref()
                .map(|i| i.src.to_string())
                .unwrap_or_else(|| "unknown".into())
        } else {
            dhcp.client_mac.clone()
        };
        if self.dhcp.len() >= MAX_SOURCES && !self.dhcp.contains_key(&key) {
            return;
        }

        let should_alert;
        let count;
        let window = self.cfg.scan_window;
        {
            let now = Instant::now();
            let state = self.dhcp.entry(key.clone()).or_default();
            if let Some(first) = state.first {
                if now.duration_since(first) > window {
                    state.first = Some(now);
                    state.count = 0;
                    state.alerted = false;
                }
            } else {
                state.first = Some(now);
            }
            state.count = state.count.saturating_add(1);
            should_alert = !state.alerted && state.count >= self.cfg.dhcp_discover_count;
            count = state.count;
            if should_alert {
                state.alerted = true;
            }
        }
        if should_alert {
            self.push(
                ts_unix_ms,
                "dhcp_discover_flood",
                "medium",
                &key,
                &format!("{count} DHCP discovers within {window:?}"),
            );
        }
    }

    fn observe_nxdomain(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        let (Some(ip), Some(AppInfo::Dns(dns))) = (&decoded.ip, &decoded.app) else {
            return;
        };
        if dns.is_query || dns.rcode != Some(3) {
            return;
        }
        // Attribute to the querier (destination of the NXDOMAIN response).
        let client = ip.dst;
        if self.nxdomain.len() >= MAX_SOURCES && !self.nxdomain.contains_key(&client) {
            return;
        }

        let should_alert;
        let count;
        let window = self.cfg.scan_window;
        let src = client.to_string();
        {
            let now = Instant::now();
            let state = self.nxdomain.entry(client).or_default();
            if let Some(first) = state.first {
                if now.duration_since(first) > window {
                    state.first = Some(now);
                    state.count = 0;
                    state.alerted = false;
                }
            } else {
                state.first = Some(now);
            }
            state.count = state.count.saturating_add(1);
            should_alert = !state.alerted && state.count >= self.cfg.dns_nxdomain_count;
            count = state.count;
            if should_alert {
                state.alerted = true;
            }
        }
        if should_alert {
            self.push(
                ts_unix_ms,
                "dns_nxdomain_burst",
                "medium",
                &src,
                &format!("{count} NXDOMAIN responses within {window:?}"),
            );
        }
    }

    fn observe_custom(&mut self, decoded: &DecodedPacket, ts_unix_ms: u64) {
        if self.cfg.custom_rules.is_empty() {
            return;
        }
        let src = decoded
            .ip
            .as_ref()
            .map(|i| i.src.to_string())
            .or_else(|| decoded.eth.as_ref().map(|e| e.src.clone()))
            .unwrap_or_else(|| "unknown".into());

        for i in 0..self.cfg.custom_rules.len() {
            let id = self.cfg.custom_rules[i].id.clone();
            if !self.cfg.rule_enabled(&id) {
                continue;
            }
            if !self.cfg.custom_rules[i].matches(decoded) {
                continue;
            }

            let corr_stats = if self.cfg.custom_rules[i].correlate.is_some() {
                match self.bump_custom_corr(i, decoded, ts_unix_ms) {
                    Some(stats) => Some(stats),
                    None => continue, // threshold not met yet
                }
            } else {
                None
            };

            let once = self.cfg.custom_rules[i].once;
            let fire = match once {
                OnceMode::None => true,
                OnceMode::Once => self.custom_once.insert(id.clone()),
                OnceMode::PerSrc => {
                    let key = (id.clone(), src.clone());
                    if self.custom_per_src.len() >= MAX_SOURCES * 4
                        && !self.custom_per_src.contains(&key)
                    {
                        false
                    } else {
                        self.custom_per_src.insert(key)
                    }
                }
            };
            if !fire {
                continue;
            }

            // With once=none + correlate, re-arm the window after each alert.
            if once == OnceMode::None {
                if let Some(spec) = self.cfg.custom_rules[i].correlate.as_ref() {
                    let track_key = spec.track.key(decoded);
                    self.custom_corr.remove(&(id.clone(), track_key));
                }
            }

            let severity = self.cfg.custom_rules[i].severity.clone();
            let detail = self.cfg.custom_rules[i].render_detail_ex(decoded, corr_stats);
            self.push(ts_unix_ms, &id, &severity, &src, &detail);
        }
    }

    /// Update correlation bucket; returns stats when threshold is met.
    fn bump_custom_corr(
        &mut self,
        rule_idx: usize,
        decoded: &DecodedPacket,
        ts_unix_ms: u64,
    ) -> Option<CorrDetail> {
        let spec = self.cfg.custom_rules[rule_idx].correlate.as_ref()?;
        let rule_id = self.cfg.custom_rules[rule_idx].id.clone();
        let track_key = spec.track.key(decoded);
        let map_key = (rule_id, track_key);

        if self.custom_corr.len() >= MAX_CORR_BUCKETS && !self.custom_corr.contains_key(&map_key) {
            return None;
        }

        let unique_field = spec.unique_field.clone();
        let window_ms = spec.window_ms;
        let window_secs = spec.window_secs;

        let bucket = self.custom_corr.entry(map_key).or_default();
        if bucket.count == 0
            || ts_unix_ms < bucket.first_ms
            || ts_unix_ms.saturating_sub(bucket.first_ms) > window_ms
        {
            bucket.first_ms = ts_unix_ms;
            bucket.count = 0;
            bucket.uniques.clear();
        }
        bucket.count = bucket.count.saturating_add(1);
        if let Some(field) = &unique_field {
            if let Some(val) = field_display(decoded, field) {
                if bucket.uniques.len() < MAX_CORR_UNIQUES || bucket.uniques.contains(&val) {
                    bucket.uniques.insert(val);
                }
            }
        }

        let match_count = bucket.count;
        let unique_n = bucket.uniques.len();
        let met = self.cfg.custom_rules[rule_idx]
            .correlate
            .as_ref()
            .is_some_and(|s| s.threshold_met(match_count, unique_n));
        if met {
            Some(CorrDetail {
                count: match_count,
                unique: unique_n,
                window_secs,
            })
        } else {
            None
        }
    }

    fn push(&mut self, ts_unix_ms: u64, rule: &str, severity: &str, src: &str, detail: &str) {
        if !self.cfg.rule_enabled(rule) {
            return;
        }
        let cooldown = self.cfg.alert_cooldown_ms;
        if cooldown > 0 {
            let key = (rule.to_string(), src.to_string());
            if let Some(&last) = self.cooldown_last.get(&key) {
                if ts_unix_ms.saturating_sub(last) < cooldown {
                    self.suppressed = self.suppressed.saturating_add(1);
                    return;
                }
            }
            if self.cooldown_last.len() < MAX_COOLDOWN_KEYS || self.cooldown_last.contains_key(&key)
            {
                self.cooldown_last.insert(key, ts_unix_ms);
            }
        }
        self.alerts.push(Alert {
            ts_unix_ms,
            rule: rule.into(),
            severity: severity.into(),
            src: src.into(),
            detail: detail.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IcmpInfo, IpInfo, TcpInfo};
    use std::net::Ipv4Addr;

    fn tcp_pkt(src: IpAddr, dst: IpAddr, dst_port: u16, flags: TcpFlags) -> DecodedPacket {
        DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst,
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(40),
            }),
            transport: Some(TransportInfo::Tcp(TcpInfo {
                src_port: 40000,
                dst_port,
                seq: 1,
                ack: 0,
                flags,
                window: 64240,
                payload_len: 0,
            })),
            ..Default::default()
        }
    }

    fn syn_pkt(src: IpAddr, dst_port: u16) -> DecodedPacket {
        tcp_pkt(
            src,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
        )
    }

    fn icmp_echo(src: IpAddr) -> DecodedPacket {
        DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                version: 4,
                protocol: 1,
                ttl: Some(64),
                total_len: Some(28),
            }),
            transport: Some(TransportInfo::Icmp(IcmpInfo {
                version: 4,
                type_u8: 8,
                code: 0,
                summary: "echo-request".into(),
            })),
            ..Default::default()
        }
    }

    #[test]
    fn detects_syn_scan() {
        let cfg = DetectConfig {
            syn_scan_ports: 5,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let mut raised = 0;
        for port in 1..=6 {
            raised += det.observe(&syn_pkt(src, port), port as u64).len();
        }
        assert!(raised >= 1);
        assert!(det.alerts().iter().any(|a| a.rule == "tcp_syn_scan"));
    }

    #[test]
    fn detects_rare_port() {
        let mut det = Detector::new(DetectConfig::default());
        let src = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let alerts = det.observe(&syn_pkt(src, 31337), 1);
        assert!(alerts.iter().any(|a| a.rule == "rare_port"));
    }

    #[test]
    fn cooldown_suppresses_repeat_rule_src() {
        use crate::packet::DnsInfo;
        let cfg = DetectConfig {
            dns_long_name: 10,
            alert_cooldown_ms: 5_000,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));
        let long = "a".repeat(20);
        let pkt = DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                version: 4,
                protocol: 17,
                ttl: Some(64),
                total_len: Some(60),
            }),
            transport: Some(TransportInfo::Udp(crate::packet::UdpInfo {
                src_port: 53_000,
                dst_port: 53,
                length: 40,
                payload_len: 32,
            })),
            app: Some(AppInfo::Dns(DnsInfo {
                is_query: true,
                id: 1,
                questions: vec![long],
                answers: vec![],
                rcode: None,
            })),
            ..Default::default()
        };
        let first = det.observe(&pkt, 1_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].rule, "dns_long_name");
        let second = det.observe(&pkt, 2_000);
        assert!(second.is_empty());
        assert_eq!(det.suppressed(), 1);
        let third = det.observe(&pkt, 7_000);
        assert_eq!(third.len(), 1);
        assert_eq!(det.alerts().len(), 2);
    }

    #[test]
    fn detects_null_fin_xmas() {
        let mut det = Detector::new(DetectConfig::default());
        let src = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

        let null = det.observe(&tcp_pkt(src, dst, 80, TcpFlags::default()), 1);
        assert!(null.iter().any(|a| a.rule == "tcp_null_scan"));

        let fin = det.observe(
            &tcp_pkt(
                src,
                dst,
                80,
                TcpFlags {
                    fin: true,
                    ..Default::default()
                },
            ),
            2,
        );
        assert!(fin.iter().any(|a| a.rule == "tcp_fin_scan"));

        let xmas = det.observe(
            &tcp_pkt(
                src,
                dst,
                80,
                TcpFlags {
                    fin: true,
                    psh: true,
                    urg: true,
                    ..Default::default()
                },
            ),
            3,
        );
        assert!(xmas.iter().any(|a| a.rule == "tcp_xmas_scan"));
    }

    #[test]
    fn detects_host_sweep() {
        let cfg = DetectConfig {
            host_sweep_hosts: 4,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));
        for i in 1..=5 {
            let pkt = tcp_pkt(
                src,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                22,
                TcpFlags {
                    syn: true,
                    ..Default::default()
                },
            );
            det.observe(&pkt, u64::from(i));
        }
        assert!(det.alerts().iter().any(|a| a.rule == "tcp_host_sweep"));
    }

    #[test]
    fn detects_icmp_echo_flood() {
        let cfg = DetectConfig {
            icmp_echo_count: 5,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6));
        for i in 1u64..=5 {
            det.observe(&icmp_echo(src), i);
        }
        assert!(det.alerts().iter().any(|a| a.rule == "icmp_echo_flood"));
    }

    #[test]
    fn detects_rst_burst() {
        let cfg = DetectConfig {
            tcp_rst_count: 3,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        for i in 1u64..=3 {
            det.observe(
                &tcp_pkt(
                    src,
                    dst,
                    80,
                    TcpFlags {
                        rst: true,
                        ..Default::default()
                    },
                ),
                i,
            );
        }
        assert!(det.alerts().iter().any(|a| a.rule == "tcp_rst_burst"));
    }

    #[test]
    fn detects_arp_mac_conflict() {
        use crate::packet::ArpInfo;
        let mut det = Detector::new(DetectConfig::default());
        let mk = |mac: &str| DecodedPacket {
            app: Some(AppInfo::Arp(ArpInfo {
                operation: "reply".into(),
                sender_mac: mac.into(),
                sender_ip: "10.0.0.50".into(),
                target_mac: "00:00:00:00:00:00".into(),
                target_ip: "10.0.0.1".into(),
            })),
            ..Default::default()
        };
        det.observe(&mk("aa:aa:aa:aa:aa:aa"), 1);
        let alerts = det.observe(&mk("bb:bb:bb:bb:bb:bb"), 2);
        assert!(alerts.iter().any(|a| a.rule == "arp_mac_conflict"));
    }

    #[test]
    fn detects_http_cleartext_auth() {
        use crate::packet::HttpInfo;
        let mut det = Detector::new(DetectConfig::default());
        let src = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let pkt = DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(100),
            }),
            app: Some(AppInfo::Http(HttpInfo {
                summary: "GET / HTTP/1.1".into(),
                host: Some("example.com".into()),
                method_or_status: "GET".into(),
                has_authorization: true,
            })),
            ..Default::default()
        };
        let alerts = det.observe(&pkt, 1);
        assert!(alerts.iter().any(|a| a.rule == "http_cleartext_auth"));
    }

    #[test]
    fn detects_tls_legacy() {
        use crate::packet::TlsInfo;
        let mut det = Detector::new(DetectConfig::default());
        let src = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let pkt = DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst: IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(100),
            }),
            app: Some(AppInfo::Tls(TlsInfo {
                handshake: "client_hello".into(),
                version: "TLS1.0".into(),
                sni: Some("old.example".into()),
                cipher_suite: None,
                ja3: None,
                ja3_hash: None,
                ja3s: None,
                ja3s_hash: None,
            })),
            ..Default::default()
        };
        let alerts = det.observe(&pkt, 1);
        assert!(alerts.iter().any(|a| a.rule == "tls_legacy_version"));
    }

    #[test]
    fn detects_dhcp_discover_flood() {
        use crate::packet::DhcpInfo;
        let cfg = DetectConfig {
            dhcp_discover_count: 3,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        for i in 1u64..=3 {
            let pkt = DecodedPacket {
                app: Some(AppInfo::Dhcp(DhcpInfo {
                    message_type: "discover".into(),
                    xid: i as u32,
                    client_mac: "aa:bb:cc:dd:ee:ff".into(),
                    client_ip: None,
                    your_ip: None,
                    server_ip: None,
                    requested_ip: None,
                    server_id: None,
                    client_hostname: None,
                })),
                ..Default::default()
            };
            det.observe(&pkt, i);
        }
        assert!(det.alerts().iter().any(|a| a.rule == "dhcp_discover_flood"));
    }

    #[test]
    fn detects_nxdomain_burst() {
        use crate::packet::DnsInfo;
        let cfg = DetectConfig {
            dns_nxdomain_count: 3,
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let client = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let server = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        for i in 1u64..=3 {
            let pkt = DecodedPacket {
                ip: Some(IpInfo {
                    src: server,
                    dst: client,
                    version: 4,
                    protocol: 17,
                    ttl: Some(64),
                    total_len: Some(80),
                }),
                app: Some(AppInfo::Dns(DnsInfo {
                    is_query: false,
                    id: i as u16,
                    questions: vec!["x.example".into()],
                    answers: vec![],
                    rcode: Some(3),
                })),
                ..Default::default()
            };
            det.observe(&pkt, i);
        }
        assert!(det.alerts().iter().any(|a| a.rule == "dns_nxdomain_burst"));
    }

    #[test]
    fn disabled_rule_does_not_fire() {
        use crate::packet::TlsInfo;
        let mut cfg = DetectConfig::default();
        cfg.disabled_rules.insert("tls_legacy_version".into());
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let pkt = DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst: IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(100),
            }),
            app: Some(AppInfo::Tls(TlsInfo {
                handshake: "client_hello".into(),
                version: "TLS1.0".into(),
                sni: Some("old.example".into()),
                cipher_suite: None,
                ja3: None,
                ja3_hash: None,
                ja3s: None,
                ja3s_hash: None,
            })),
            ..Default::default()
        };
        let alerts = det.observe(&pkt, 1);
        assert!(alerts.is_empty());
    }

    #[test]
    fn custom_expression_rule_fires_once_per_src() {
        use crate::expr::{compile_custom_rules, CustomRuleDef, Expr, Predicate, Scalar};
        use crate::packet::SshInfo;

        let defs = vec![CustomRuleDef {
            id: "ssh_alt_port".into(),
            severity: "medium".into(),
            description: String::new(),
            detail: Some("SSH on {tcp.dst_port}".into()),
            once: "per_src".into(),
            correlate: None,
            when: Expr::And {
                and: vec![
                    Expr::Pred(Box::new(Predicate {
                        field: "app".into(),
                        eq: Some(Scalar::String("ssh".into())),
                        ne: None,
                        gt: None,
                        gte: None,
                        lt: None,
                        lte: None,
                        in_list: None,
                        not_in: None,
                        contains: None,
                        starts_with: None,
                        ends_with: None,
                        exists: None,
                        in_cidr: None,
                        not_in_cidr: None,
                    })),
                    Expr::Pred(Box::new(Predicate {
                        field: "tcp.dst_port".into(),
                        eq: None,
                        ne: None,
                        gt: None,
                        gte: None,
                        lt: None,
                        lte: None,
                        in_list: None,
                        not_in: Some(vec![Scalar::Number(22.0)]),
                        contains: None,
                        starts_with: None,
                        ends_with: None,
                        exists: None,
                        in_cidr: None,
                        not_in_cidr: None,
                    })),
                ],
            },
        }];
        let cfg = DetectConfig {
            custom_rules: compile_custom_rules(&defs).unwrap(),
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let pkt = DecodedPacket {
            ip: Some(IpInfo {
                src,
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(80),
            }),
            transport: Some(TransportInfo::Tcp(TcpInfo {
                src_port: 40000,
                dst_port: 2222,
                seq: 1,
                ack: 1,
                flags: TcpFlags {
                    ack: true,
                    ..Default::default()
                },
                window: 64240,
                payload_len: 20,
            })),
            app: Some(AppInfo::Ssh(SshInfo {
                banner: "SSH-2.0-OpenSSH".into(),
                proto: "2.0".into(),
            })),
            ..Default::default()
        };
        let first = det.observe(&pkt, 1);
        let second = det.observe(&pkt, 2);
        assert!(first.iter().any(|a| a.rule == "ssh_alt_port"));
        assert!(second.is_empty());
    }

    #[test]
    fn custom_correlate_count_window() {
        use crate::expr::{
            compile_custom_rules, CorrelateDef, CustomRuleDef, Expr, Predicate, Scalar,
        };

        let defs = vec![CustomRuleDef {
            id: "syn_burst".into(),
            severity: "high".into(),
            description: String::new(),
            detail: Some("{count} SYNs from {ip.src} in {window_secs}s".into()),
            once: "per_src".into(),
            correlate: Some(CorrelateDef {
                window_secs: 10,
                track: "by_src".into(),
                count: Some(3),
                unique_field: None,
                unique_count: None,
            }),
            when: Expr::Pred(Box::new(Predicate {
                field: "tcp.flags.syn".into(),
                eq: Some(Scalar::Bool(true)),
                ne: None,
                gt: None,
                gte: None,
                lt: None,
                lte: None,
                in_list: None,
                not_in: None,
                contains: None,
                starts_with: None,
                ends_with: None,
                exists: None,
                in_cidr: None,
                not_in_cidr: None,
            })),
        }];
        let cfg = DetectConfig {
            custom_rules: compile_custom_rules(&defs).unwrap(),
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));
        let mut last = Vec::new();
        for i in 1u64..=3 {
            let pkt = tcp_pkt(
                src,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                80,
                TcpFlags {
                    syn: true,
                    ..Default::default()
                },
            );
            last = det.observe(&pkt, i * 1000);
        }
        assert!(
            last.iter()
                .any(|a| a.rule == "syn_burst" && a.detail.contains("3 SYNs")),
            "got {last:?}"
        );
        assert_eq!(
            det.alerts()
                .iter()
                .filter(|a| a.rule == "syn_burst")
                .count(),
            1
        );
    }

    #[test]
    fn custom_correlate_unique_ports() {
        use crate::expr::{
            compile_custom_rules, CorrelateDef, CustomRuleDef, Expr, Predicate, Scalar,
        };

        let defs = vec![CustomRuleDef {
            id: "port_spray".into(),
            severity: "medium".into(),
            description: String::new(),
            detail: Some("{unique} ports from {ip.src}".into()),
            once: "per_src".into(),
            correlate: Some(CorrelateDef {
                window_secs: 30,
                track: "by_src".into(),
                count: None,
                unique_field: Some("tcp.dst_port".into()),
                unique_count: Some(3),
            }),
            when: Expr::Pred(Box::new(Predicate {
                field: "tcp.flags.syn".into(),
                eq: Some(Scalar::Bool(true)),
                ne: None,
                gt: None,
                gte: None,
                lt: None,
                lte: None,
                in_list: None,
                not_in: None,
                contains: None,
                starts_with: None,
                ends_with: None,
                exists: None,
                in_cidr: None,
                not_in_cidr: None,
            })),
        }];
        let cfg = DetectConfig {
            custom_rules: compile_custom_rules(&defs).unwrap(),
            ..DetectConfig::default()
        };
        let mut det = Detector::new(cfg);
        let src = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));
        let dst = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6));
        let flags = TcpFlags {
            syn: true,
            ..Default::default()
        };
        assert!(det.observe(&tcp_pkt(src, dst, 21, flags), 1).is_empty());
        assert!(det.observe(&tcp_pkt(src, dst, 22, flags), 2).is_empty());
        let third = det.observe(&tcp_pkt(src, dst, 23, flags), 3);
        assert!(
            third
                .iter()
                .any(|a| a.rule == "port_spray" && a.detail.contains("3 ports")),
            "got {third:?}"
        );
    }
}
