//! Authorization scope — mandatory allowlist for active modules.

use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Hard cap so a bad scope cannot expand into millions of probes.
pub const DEFAULT_MAX_HOSTS: usize = 1024;
pub const DEFAULT_MAX_PPS: u32 = 50;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 800;

/// Written authorization scope loaded from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Authorization / ticket identifier (required for audit).
    pub ticket_id: String,
    /// Human operator name / ID.
    pub operator: String,
    /// Organization or engagement name.
    #[serde(default)]
    pub organization: String,
    /// Explicit acknowledgment that use is authorized.
    pub authorized: bool,
    /// Target hosts or CIDRs (e.g. "10.0.0.5", "192.168.1.0/24").
    pub targets: Vec<String>,
    /// Hosts/CIDRs that must never be touched.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// TCP ports to probe.
    pub ports: Vec<u16>,
    /// Max probes per second.
    #[serde(default = "default_max_pps")]
    pub max_pps: u32,
    /// Connect timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub connect_timeout_ms: u64,
    /// Max hosts after CIDR expansion.
    #[serde(default = "default_max_hosts")]
    pub max_hosts: usize,
    /// Optional expiry as Unix seconds; reject if in the past.
    #[serde(default)]
    pub valid_until_unix: Option<u64>,
}

fn default_max_pps() -> u32 {
    DEFAULT_MAX_PPS
}
fn default_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}
fn default_max_hosts() -> usize {
    DEFAULT_MAX_HOSTS
}

impl Scope {
    /// Load and validate a scope file from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read scope file {}", path.display()))?;
        let scope: Self = serde_json::from_str(&raw)
            .with_context(|| format!("invalid JSON in scope file {}", path.display()))?;
        scope.validate()?;
        Ok(scope)
    }

    /// Structural + policy validation.
    pub fn validate(&self) -> Result<()> {
        if self.ticket_id.trim().is_empty() {
            bail!("scope.ticket_id is required");
        }
        if self.operator.trim().is_empty() {
            bail!("scope.operator is required");
        }
        if !self.authorized {
            bail!("scope.authorized must be true — refusing unauthorized engagement");
        }
        if self.targets.is_empty() {
            bail!("scope.targets must list at least one host or CIDR");
        }
        if self.ports.is_empty() {
            bail!("scope.ports must list at least one TCP port");
        }
        if self.ports.contains(&0) {
            bail!("scope.ports cannot include port 0");
        }
        if self.max_pps == 0 {
            bail!("scope.max_pps must be > 0");
        }
        if self.max_hosts == 0 {
            bail!("scope.max_hosts must be > 0");
        }
        if self.connect_timeout_ms == 0 {
            bail!("scope.connect_timeout_ms must be > 0");
        }

        if let Some(until) = self.valid_until_unix {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > until {
                bail!("scope.valid_until_unix has expired ({until})");
            }
        }

        // Ensure every target/exclude parses.
        for t in &self.targets {
            parse_target(t).with_context(|| format!("invalid target '{t}'"))?;
        }
        for e in &self.exclude {
            parse_target(e).with_context(|| format!("invalid exclude '{e}'"))?;
        }

        Ok(())
    }

    /// Expand targets into individual IPs, applying excludes and max_hosts.
    pub fn expand_hosts(&self) -> Result<Vec<IpAddr>> {
        let excludes = self
            .exclude
            .iter()
            .map(|e| parse_target(e))
            .collect::<Result<Vec<_>>>()?;

        let mut hosts = Vec::new();
        for t in &self.targets {
            let net = parse_target(t)?;
            for ip in net.hosts() {
                if excludes.iter().any(|ex| ex.contains(&ip)) {
                    continue;
                }
                // Skip network/broadcast for IPv4 nets larger than /31 via IpNet::hosts
                hosts.push(ip);
                if hosts.len() > self.max_hosts {
                    bail!(
                        "target expansion exceeds max_hosts={} — narrow the CIDR or raise max_hosts deliberately",
                        self.max_hosts
                    );
                }
            }
            // Single-host /32 or /128: IpNet::hosts() yields the address.
            // For a lone IP written as host, parse_target makes /32 or /128.
            if matches!(net, IpNet::V4(n) if n.prefix_len() == 32)
                || matches!(net, IpNet::V6(n) if n.prefix_len() == 128)
            {
                // hosts() already included it; nothing extra.
            }
        }

        if hosts.is_empty() {
            bail!("no hosts remain after expansion and excludes");
        }
        hosts.sort();
        hosts.dedup();
        Ok(hosts)
    }

    /// True if an IP is inside targets and not excluded.
    pub fn allows_ip(&self, ip: IpAddr) -> Result<bool> {
        let targets = self
            .targets
            .iter()
            .map(|t| parse_target(t))
            .collect::<Result<Vec<_>>>()?;
        let excludes = self
            .exclude
            .iter()
            .map(|e| parse_target(e))
            .collect::<Result<Vec<_>>>()?;

        if excludes.iter().any(|ex| ex.contains(&ip)) {
            return Ok(false);
        }
        Ok(targets.iter().any(|t| t.contains(&ip)))
    }
}

fn parse_target(s: &str) -> Result<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = s
        .parse()
        .with_context(|| format!("expected IP or CIDR, got '{s}'"))?;
    Ok(IpNet::from(ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_json() -> String {
        r#"{
          "ticket_id": "LAB-001",
          "operator": "tester",
          "organization": "lab",
          "authorized": true,
          "targets": ["127.0.0.1", "10.0.0.0/30"],
          "exclude": ["10.0.0.1"],
          "ports": [80, 443],
          "max_pps": 20,
          "max_hosts": 16
        }"#
        .into()
    }

    #[test]
    fn loads_and_expands() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", sample_json()).unwrap();
        let scope = Scope::load(f.path()).unwrap();
        let hosts = scope.expand_hosts().unwrap();
        assert!(hosts.contains(&"127.0.0.1".parse().unwrap()));
        assert!(!hosts.contains(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_unauthorized() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{"ticket_id":"x","operator":"y","authorized":false,"targets":["127.0.0.1"],"ports":[80]}}"#
        )
        .unwrap();
        assert!(Scope::load(f.path()).is_err());
    }
}
