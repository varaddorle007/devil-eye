//! Custom IDS rule expressions (safe, bounded YAML predicates — no scripts).

use std::net::IpAddr;

use anyhow::{bail, Result};
use ipnet::IpNet;
use serde::Deserialize;

use crate::packet::{AppInfo, DecodedPacket, TransportInfo};

const MAX_CUSTOM_RULES: usize = 64;
const MAX_PRED_NODES: usize = 64;
const MAX_DETAIL_LEN: usize = 240;

/// One custom rule as authored in a YAML pack.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRuleDef {
    pub id: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub description: String,
    /// Alert detail template; `{field}` placeholders are expanded.
    #[serde(default)]
    pub detail: Option<String>,
    /// `none` (every match), `once` (global), `per_src` (default).
    #[serde(default = "default_once")]
    pub once: String,
    /// Optional sliding-window correlation (Suricata-style threshold).
    #[serde(default)]
    pub correlate: Option<CorrelateDef>,
    pub when: Expr,
}

fn default_severity() -> String {
    "medium".into()
}

fn default_once() -> String {
    "per_src".into()
}

fn default_track() -> String {
    "by_src".into()
}

/// Sliding-window aggregation for a custom rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CorrelateDef {
    /// Window length in seconds (packet timestamps).
    pub window_secs: u64,
    /// `by_src` (default), `by_dst`, `by_pair`, or `global`.
    #[serde(default = "default_track")]
    pub track: String,
    /// Minimum matching packets in the window.
    #[serde(default)]
    pub count: Option<usize>,
    /// Field whose distinct values are counted (e.g. `tcp.dst_port`).
    #[serde(default)]
    pub unique_field: Option<String>,
    /// Minimum distinct values of `unique_field` in the window.
    #[serde(default)]
    pub unique_count: Option<usize>,
}

/// How correlation state is keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackMode {
    BySrc,
    ByDst,
    ByPair,
    Global,
}

impl TrackMode {
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "by_src" | "src" | "source" => Ok(Self::BySrc),
            "by_dst" | "dst" | "dest" | "destination" => Ok(Self::ByDst),
            "by_pair" | "pair" | "flow" => Ok(Self::ByPair),
            "global" | "all" => Ok(Self::Global),
            other => bail!("correlate.track must be by_src|by_dst|by_pair|global (got {other})"),
        }
    }

    /// Stable key for detector state maps.
    pub fn key(self, pkt: &DecodedPacket) -> String {
        let src = pkt
            .ip
            .as_ref()
            .map(|i| i.src.to_string())
            .unwrap_or_else(|| "unknown".into());
        let dst = pkt
            .ip
            .as_ref()
            .map(|i| i.dst.to_string())
            .unwrap_or_else(|| "unknown".into());
        match self {
            Self::BySrc => src,
            Self::ByDst => dst,
            Self::ByPair => format!("{src}->{dst}"),
            Self::Global => "*".into(),
        }
    }
}

/// Compiled correlation knobs.
#[derive(Debug, Clone)]
pub struct CorrelateSpec {
    pub window_ms: u64,
    pub window_secs: u64,
    pub track: TrackMode,
    pub count: Option<usize>,
    pub unique_field: Option<String>,
    pub unique_count: Option<usize>,
}

impl CorrelateSpec {
    fn compile(def: &CorrelateDef, rule_id: &str) -> Result<Self> {
        if def.window_secs == 0 {
            bail!("custom rule '{rule_id}': correlate.window_secs must be > 0");
        }
        if def.window_secs > 86_400 {
            bail!("custom rule '{rule_id}': correlate.window_secs max is 86400");
        }
        let track = TrackMode::parse(&def.track)?;
        let count = def.count;
        let unique_field = def
            .unique_field
            .as_ref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let unique_count = def.unique_count;

        if count.is_none() && unique_field.is_none() {
            bail!(
                "custom rule '{rule_id}': correlate needs count and/or unique_field+unique_count"
            );
        }
        if let Some(n) = count {
            if n == 0 {
                bail!("custom rule '{rule_id}': correlate.count must be > 0");
            }
        }
        if unique_field.is_some() {
            match unique_count {
                Some(n) if n > 0 => {}
                _ => bail!("custom rule '{rule_id}': unique_field requires unique_count > 0"),
            }
        } else if unique_count.is_some() {
            bail!("custom rule '{rule_id}': unique_count requires unique_field");
        }

        Ok(Self {
            window_ms: def.window_secs.saturating_mul(1000),
            window_secs: def.window_secs,
            track,
            count,
            unique_field,
            unique_count,
        })
    }

    /// Whether current bucket stats meet thresholds.
    pub fn threshold_met(&self, match_count: usize, unique_count: usize) -> bool {
        let count_ok = self.count.map(|n| match_count >= n).unwrap_or(true);
        let unique_ok = self.unique_count.map(|n| unique_count >= n).unwrap_or(true);
        count_ok && unique_ok
    }
}

/// Stats substituted into detail templates for correlated alerts.
#[derive(Debug, Clone, Copy, Default)]
pub struct CorrDetail {
    pub count: usize,
    pub unique: usize,
    pub window_secs: u64,
}

/// Boolean expression tree.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Expr {
    And { and: Vec<Expr> },
    Or { or: Vec<Expr> },
    Not { not: Box<Expr> },
    Pred(Box<Predicate>),
}

/// Single field comparison.
#[derive(Debug, Clone, Deserialize)]
pub struct Predicate {
    pub field: String,
    #[serde(default)]
    pub eq: Option<Scalar>,
    #[serde(default)]
    pub ne: Option<Scalar>,
    #[serde(default)]
    pub gt: Option<f64>,
    #[serde(default)]
    pub gte: Option<f64>,
    #[serde(default)]
    pub lt: Option<f64>,
    #[serde(default)]
    pub lte: Option<f64>,
    #[serde(default, rename = "in")]
    pub in_list: Option<Vec<Scalar>>,
    #[serde(default)]
    pub not_in: Option<Vec<Scalar>>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub starts_with: Option<String>,
    #[serde(default)]
    pub ends_with: Option<String>,
    #[serde(default)]
    pub exists: Option<bool>,
    #[serde(default)]
    pub in_cidr: Option<Vec<String>>,
    #[serde(default)]
    pub not_in_cidr: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Scalar {
    Bool(bool),
    Number(f64),
    String(String),
}

impl Scalar {
    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::String(s) => match s.to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => Some(true),
                "false" | "no" | "0" => Some(false),
                _ => None,
            },
            Self::Number(n) => Some(*n != 0.0),
        }
    }

    fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::String(s) => s.parse().ok(),
            Self::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        }
    }

    fn as_string(&self) -> String {
        match self {
            Self::String(s) => s.clone(),
            Self::Number(n) => {
                if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
            Self::Bool(b) => b.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnceMode {
    None,
    Once,
    PerSrc,
}

impl OnceMode {
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" | "every" | "always" => Ok(Self::None),
            "once" | "global" => Ok(Self::Once),
            "per_src" | "persrc" | "src" => Ok(Self::PerSrc),
            other => bail!("custom rule once= must be none|once|per_src (got {other})"),
        }
    }
}

/// Compiled custom rule ready for the detector.
#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub severity: String,
    pub detail_template: String,
    pub once: OnceMode,
    pub correlate: Option<CorrelateSpec>,
    pub when: Expr,
}

impl CustomRule {
    pub fn compile(def: CustomRuleDef) -> Result<Self> {
        let id = def.id.trim().to_string();
        validate_rule_id(&id)?;
        let severity = def.severity.trim().to_ascii_lowercase();
        if !matches!(
            severity.as_str(),
            "low" | "medium" | "high" | "info" | "critical"
        ) {
            bail!("custom rule '{id}': severity must be low|medium|high|info|critical");
        }
        let once = OnceMode::parse(&def.once)?;
        let nodes = count_nodes(&def.when);
        if nodes == 0 || nodes > MAX_PRED_NODES {
            bail!("custom rule '{id}': expression too large or empty ({nodes} nodes)");
        }
        validate_expr(&def.when).map_err(|e| anyhow::anyhow!("custom rule '{id}': {e}"))?;
        let correlate = def
            .correlate
            .as_ref()
            .map(|c| CorrelateSpec::compile(c, &id))
            .transpose()?;

        let detail_template = def
            .detail
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                if def.description.trim().is_empty() {
                    None
                } else {
                    Some(def.description.clone())
                }
            })
            .unwrap_or_else(|| format!("custom rule {id} matched"));

        Ok(Self {
            id,
            severity,
            detail_template,
            once,
            correlate,
            when: def.when,
        })
    }

    pub fn matches(&self, pkt: &DecodedPacket) -> bool {
        eval_expr(&self.when, pkt)
    }

    pub fn render_detail(&self, pkt: &DecodedPacket) -> String {
        self.render_detail_ex(pkt, None)
    }

    pub fn render_detail_ex(&self, pkt: &DecodedPacket, corr: Option<CorrDetail>) -> String {
        let mut out = self.detail_template.clone();
        for field in [
            "ip.src",
            "ip.dst",
            "tcp.src_port",
            "tcp.dst_port",
            "udp.src_port",
            "udp.dst_port",
            "app",
            "dns.qname",
            "http.host",
            "http.method",
            "tls.sni",
            "tls.version",
            "tls.ja3",
            "tls.ja3_hash",
            "tls.ja3s",
            "tls.ja3s_hash",
            "ssh.banner",
            "dhcp.message_type",
        ] {
            let key = format!("{{{field}}}");
            if out.contains(&key) {
                let val = lookup_field(pkt, field)
                    .map(|v| v.display())
                    .unwrap_or_else(|| "-".into());
                out = out.replace(&key, &val);
            }
        }
        if let Some(c) = corr {
            out = out.replace("{count}", &c.count.to_string());
            out = out.replace("{unique}", &c.unique.to_string());
            out = out.replace("{window_secs}", &c.window_secs.to_string());
        }
        if out.len() > MAX_DETAIL_LEN {
            out.truncate(MAX_DETAIL_LEN);
            out.push('…');
        }
        out
    }
}

/// Compile and bound-check a list of custom rule definitions.
pub fn compile_custom_rules(defs: &[CustomRuleDef]) -> Result<Vec<CustomRule>> {
    if defs.len() > MAX_CUSTOM_RULES {
        bail!(
            "too many custom_rules ({} > max {MAX_CUSTOM_RULES})",
            defs.len()
        );
    }
    let mut out = Vec::with_capacity(defs.len());
    let mut seen = std::collections::HashSet::new();
    for def in defs {
        let rule = CustomRule::compile(def.clone())?;
        if !seen.insert(rule.id.to_ascii_lowercase()) {
            bail!("duplicate custom rule id '{}'", rule.id);
        }
        out.push(rule);
    }
    Ok(out)
}

fn validate_rule_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        bail!("custom rule id must be 1–64 characters");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!("custom rule id '{id}' must be alphanumeric/underscore/hyphen");
    }
    // Avoid colliding with reserved built-in naming if prefixed? Allow any unique id.
    Ok(())
}

fn count_nodes(expr: &Expr) -> usize {
    match expr {
        Expr::And { and } | Expr::Or { or: and } => 1 + and.iter().map(count_nodes).sum::<usize>(),
        Expr::Not { not } => 1 + count_nodes(not),
        Expr::Pred(_) => 1,
    }
}

fn validate_expr(expr: &Expr) -> Result<()> {
    match expr {
        Expr::And { and } | Expr::Or { or: and } => {
            if and.is_empty() {
                bail!("and/or must contain at least one predicate");
            }
            for child in and {
                validate_expr(child)?;
            }
            Ok(())
        }
        Expr::Not { not } => validate_expr(not),
        Expr::Pred(p) => validate_pred(p),
    }
}

fn validate_pred(p: &Predicate) -> Result<()> {
    if p.field.trim().is_empty() {
        bail!("predicate field must not be empty");
    }
    let ops = [
        p.eq.is_some(),
        p.ne.is_some(),
        p.gt.is_some(),
        p.gte.is_some(),
        p.lt.is_some(),
        p.lte.is_some(),
        p.in_list.is_some(),
        p.not_in.is_some(),
        p.contains.is_some(),
        p.starts_with.is_some(),
        p.ends_with.is_some(),
        p.exists.is_some(),
        p.in_cidr.is_some(),
        p.not_in_cidr.is_some(),
    ]
    .iter()
    .filter(|&&x| x)
    .count();
    if ops != 1 {
        bail!(
            "field '{}' must have exactly one operator (found {ops})",
            p.field
        );
    }
    if let Some(list) = &p.in_cidr {
        for cidr in list {
            cidr.parse::<IpNet>()
                .map_err(|e| anyhow::anyhow!("invalid in_cidr '{cidr}': {e}"))?;
        }
    }
    if let Some(list) = &p.not_in_cidr {
        for cidr in list {
            cidr.parse::<IpNet>()
                .map_err(|e| anyhow::anyhow!("invalid not_in_cidr '{cidr}': {e}"))?;
        }
    }
    Ok(())
}

fn eval_expr(expr: &Expr, pkt: &DecodedPacket) -> bool {
    match expr {
        Expr::And { and } => and.iter().all(|e| eval_expr(e, pkt)),
        Expr::Or { or } => or.iter().any(|e| eval_expr(e, pkt)),
        Expr::Not { not } => !eval_expr(not, pkt),
        Expr::Pred(p) => eval_pred(p, pkt),
    }
}

fn eval_pred(p: &Predicate, pkt: &DecodedPacket) -> bool {
    let value = lookup_field(pkt, &p.field);

    if let Some(want_exists) = p.exists {
        return value.is_some() == want_exists;
    }

    let Some(val) = value else {
        return false;
    };

    if let Some(eq) = &p.eq {
        return values_equal(&val, eq);
    }
    if let Some(ne) = &p.ne {
        return !values_equal(&val, ne);
    }
    if let Some(n) = p.gt {
        return val.as_number().is_some_and(|v| v > n);
    }
    if let Some(n) = p.gte {
        return val.as_number().is_some_and(|v| v >= n);
    }
    if let Some(n) = p.lt {
        return val.as_number().is_some_and(|v| v < n);
    }
    if let Some(n) = p.lte {
        return val.as_number().is_some_and(|v| v <= n);
    }
    if let Some(list) = &p.in_list {
        return list.iter().any(|s| values_equal(&val, s));
    }
    if let Some(list) = &p.not_in {
        return list.iter().all(|s| !values_equal(&val, s));
    }
    if let Some(sub) = &p.contains {
        return val
            .display()
            .to_ascii_lowercase()
            .contains(&sub.to_ascii_lowercase());
    }
    if let Some(prefix) = &p.starts_with {
        return val
            .display()
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase());
    }
    if let Some(suffix) = &p.ends_with {
        return val
            .display()
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase());
    }
    if let Some(cidrs) = &p.in_cidr {
        return ip_in_cidrs(&val, cidrs);
    }
    if let Some(cidrs) = &p.not_in_cidr {
        return !ip_in_cidrs(&val, cidrs);
    }
    false
}

fn values_equal(val: &FieldValue, scalar: &Scalar) -> bool {
    match val {
        FieldValue::Bool(b) => scalar.as_bool() == Some(*b),
        FieldValue::Number(n) => scalar
            .as_number()
            .is_some_and(|s| (s - *n).abs() < f64::EPSILON),
        FieldValue::String(s) => s.eq_ignore_ascii_case(&scalar.as_string()),
    }
}

fn ip_in_cidrs(val: &FieldValue, cidrs: &[String]) -> bool {
    let FieldValue::String(s) = val else {
        return false;
    };
    let Ok(ip) = s.parse::<IpAddr>() else {
        return false;
    };
    cidrs.iter().any(|c| {
        c.parse::<IpNet>()
            .map(|net| net.contains(&ip))
            .unwrap_or(false)
    })
}

#[derive(Debug, Clone)]
enum FieldValue {
    Bool(bool),
    Number(f64),
    String(String),
}

impl FieldValue {
    fn display(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Number(n) => {
                if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
            Self::String(s) => s.clone(),
        }
    }

    fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Self::String(s) => s.parse().ok(),
        }
    }
}

/// Resolve a dotted field path from a decoded packet.
/// Display string for a field (used by unique-value correlation).
pub fn field_display(pkt: &DecodedPacket, field: &str) -> Option<String> {
    lookup_field(pkt, field).map(|v| v.display())
}

fn lookup_field(pkt: &DecodedPacket, field: &str) -> Option<FieldValue> {
    let f = field.trim().to_ascii_lowercase();
    match f.as_str() {
        "payload_len" => Some(FieldValue::Number(pkt.payload_len as f64)),
        "app" => pkt.app.as_ref().map(|a| {
            FieldValue::String(
                match a {
                    AppInfo::Dns(_) => "dns",
                    AppInfo::Http(_) => "http",
                    AppInfo::Ssh(_) => "ssh",
                    AppInfo::Tls(_) => "tls",
                    AppInfo::Arp(_) => "arp",
                    AppInfo::Dhcp(_) => "dhcp",
                }
                .into(),
            )
        }),
        "eth.src" => pkt.eth.as_ref().map(|e| FieldValue::String(e.src.clone())),
        "eth.dst" => pkt.eth.as_ref().map(|e| FieldValue::String(e.dst.clone())),
        "ip.src" => pkt
            .ip
            .as_ref()
            .map(|i| FieldValue::String(i.src.to_string())),
        "ip.dst" => pkt
            .ip
            .as_ref()
            .map(|i| FieldValue::String(i.dst.to_string())),
        "ip.version" => pkt
            .ip
            .as_ref()
            .map(|i| FieldValue::Number(f64::from(i.version))),
        "ip.protocol" => pkt
            .ip
            .as_ref()
            .map(|i| FieldValue::Number(f64::from(i.protocol))),
        "ip.ttl" => pkt
            .ip
            .as_ref()
            .and_then(|i| i.ttl.map(|t| FieldValue::Number(f64::from(t)))),
        "tcp.src_port" => tcp(pkt).map(|t| FieldValue::Number(f64::from(t.src_port))),
        "tcp.dst_port" => tcp(pkt).map(|t| FieldValue::Number(f64::from(t.dst_port))),
        "tcp.payload_len" => tcp(pkt).map(|t| FieldValue::Number(t.payload_len as f64)),
        "tcp.flags.syn" => tcp(pkt).map(|t| FieldValue::Bool(t.flags.syn)),
        "tcp.flags.ack" => tcp(pkt).map(|t| FieldValue::Bool(t.flags.ack)),
        "tcp.flags.fin" => tcp(pkt).map(|t| FieldValue::Bool(t.flags.fin)),
        "tcp.flags.rst" => tcp(pkt).map(|t| FieldValue::Bool(t.flags.rst)),
        "tcp.flags.psh" => tcp(pkt).map(|t| FieldValue::Bool(t.flags.psh)),
        "tcp.flags.urg" => tcp(pkt).map(|t| FieldValue::Bool(t.flags.urg)),
        "udp.src_port" => udp(pkt).map(|u| FieldValue::Number(f64::from(u.src_port))),
        "udp.dst_port" => udp(pkt).map(|u| FieldValue::Number(f64::from(u.dst_port))),
        "udp.payload_len" => udp(pkt).map(|u| FieldValue::Number(u.payload_len as f64)),
        "icmp.type" => icmp(pkt).map(|i| FieldValue::Number(f64::from(i.type_u8))),
        "icmp.code" => icmp(pkt).map(|i| FieldValue::Number(f64::from(i.code))),
        "dns.is_query" => dns(pkt).map(|d| FieldValue::Bool(d.is_query)),
        "dns.qname" => dns(pkt).and_then(|d| d.questions.first().cloned().map(FieldValue::String)),
        "dns.qname_len" => dns(pkt).and_then(|d| {
            d.questions
                .first()
                .map(|q| FieldValue::Number(q.len() as f64))
        }),
        "dns.rcode" => dns(pkt).and_then(|d| d.rcode.map(|c| FieldValue::Number(f64::from(c)))),
        "http.method" | "http.method_or_status" => {
            http(pkt).map(|h| FieldValue::String(h.method_or_status.clone()))
        }
        "http.host" => http(pkt).and_then(|h| h.host.clone().map(FieldValue::String)),
        "http.has_authorization" => http(pkt).map(|h| FieldValue::Bool(h.has_authorization)),
        "ssh.proto" => ssh(pkt).map(|s| FieldValue::String(s.proto.clone())),
        "ssh.banner" => ssh(pkt).map(|s| FieldValue::String(s.banner.clone())),
        "tls.version" => tls(pkt).map(|t| FieldValue::String(t.version.clone())),
        "tls.handshake" => tls(pkt).map(|t| FieldValue::String(t.handshake.clone())),
        "tls.sni" => tls(pkt).and_then(|t| t.sni.clone().map(FieldValue::String)),
        "tls.ja3" => tls(pkt).and_then(|t| t.ja3.clone().map(FieldValue::String)),
        "tls.ja3_hash" => tls(pkt).and_then(|t| t.ja3_hash.clone().map(FieldValue::String)),
        "tls.ja3s" => tls(pkt).and_then(|t| t.ja3s.clone().map(FieldValue::String)),
        "tls.ja3s_hash" => tls(pkt).and_then(|t| t.ja3s_hash.clone().map(FieldValue::String)),
        "arp.operation" => arp(pkt).map(|a| FieldValue::String(a.operation.clone())),
        "arp.sender_ip" => arp(pkt).map(|a| FieldValue::String(a.sender_ip.clone())),
        "dhcp.message_type" => dhcp(pkt).map(|d| FieldValue::String(d.message_type.clone())),
        "dhcp.hostname" => {
            dhcp(pkt).and_then(|d| d.client_hostname.clone().map(FieldValue::String))
        }
        _ => None,
    }
}

fn tcp(pkt: &DecodedPacket) -> Option<&crate::packet::TcpInfo> {
    match &pkt.transport {
        Some(TransportInfo::Tcp(t)) => Some(t),
        _ => None,
    }
}

fn udp(pkt: &DecodedPacket) -> Option<&crate::packet::UdpInfo> {
    match &pkt.transport {
        Some(TransportInfo::Udp(u)) => Some(u),
        _ => None,
    }
}

fn icmp(pkt: &DecodedPacket) -> Option<&crate::packet::IcmpInfo> {
    match &pkt.transport {
        Some(TransportInfo::Icmp(i)) => Some(i),
        _ => None,
    }
}

fn dns(pkt: &DecodedPacket) -> Option<&crate::packet::DnsInfo> {
    match &pkt.app {
        Some(AppInfo::Dns(d)) => Some(d),
        _ => None,
    }
}

fn http(pkt: &DecodedPacket) -> Option<&crate::packet::HttpInfo> {
    match &pkt.app {
        Some(AppInfo::Http(h)) => Some(h),
        _ => None,
    }
}

fn ssh(pkt: &DecodedPacket) -> Option<&crate::packet::SshInfo> {
    match &pkt.app {
        Some(AppInfo::Ssh(s)) => Some(s),
        _ => None,
    }
}

fn tls(pkt: &DecodedPacket) -> Option<&crate::packet::TlsInfo> {
    match &pkt.app {
        Some(AppInfo::Tls(t)) => Some(t),
        _ => None,
    }
}

fn arp(pkt: &DecodedPacket) -> Option<&crate::packet::ArpInfo> {
    match &pkt.app {
        Some(AppInfo::Arp(a)) => Some(a),
        _ => None,
    }
}

fn dhcp(pkt: &DecodedPacket) -> Option<&crate::packet::DhcpInfo> {
    match &pkt.app {
        Some(AppInfo::Dhcp(d)) => Some(d),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IpInfo, SshInfo, TcpFlags, TcpInfo};
    use std::net::Ipv4Addr;

    fn ssh_pkt(dst_port: u16) -> DecodedPacket {
        DecodedPacket {
            ip: Some(IpInfo {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                version: 4,
                protocol: 6,
                ttl: Some(64),
                total_len: Some(100),
            }),
            transport: Some(TransportInfo::Tcp(TcpInfo {
                src_port: 50000,
                dst_port,
                seq: 1,
                ack: 0,
                flags: TcpFlags {
                    syn: false,
                    ack: true,
                    ..Default::default()
                },
                window: 64240,
                payload_len: 20,
            })),
            app: Some(AppInfo::Ssh(SshInfo {
                banner: "SSH-2.0-OpenSSH_9.0".into(),
                proto: "2.0".into(),
            })),
            ..Default::default()
        }
    }

    #[test]
    fn matches_and_expression() {
        let rule = CustomRule::compile(CustomRuleDef {
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
        })
        .unwrap();

        assert!(rule.matches(&ssh_pkt(2222)));
        assert!(!rule.matches(&ssh_pkt(22)));
        assert_eq!(rule.render_detail(&ssh_pkt(2222)), "SSH on 2222");
    }

    #[test]
    fn rejects_bad_id() {
        let err = CustomRule::compile(CustomRuleDef {
            id: "bad id!".into(),
            severity: "low".into(),
            description: String::new(),
            detail: None,
            once: "once".into(),
            correlate: None,
            when: Expr::Pred(Box::new(Predicate {
                field: "app".into(),
                eq: Some(Scalar::String("dns".into())),
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
        })
        .unwrap_err();
        assert!(err.to_string().contains("alphanumeric"));
    }

    #[test]
    fn cidr_match() {
        let pkt = ssh_pkt(22);
        let pred = Predicate {
            field: "ip.src".into(),
            eq: None,
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
            in_cidr: Some(vec!["10.0.0.0/8".into()]),
            not_in_cidr: None,
        };
        assert!(eval_pred(&pred, &pkt));
    }
}
