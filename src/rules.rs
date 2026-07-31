//! YAML rule packs for IDS-lite threshold / port / enablement / custom expressions.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::detect::DetectConfig;
use crate::expr::{compile_custom_rules, CustomRuleDef};

/// On-disk rule pack (YAML).
#[derive(Debug, Clone, Deserialize)]
pub struct RulePack {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: u32,
    /// Aggregation window in seconds (scan/sweep/ICMP/RST/DHCP/NXDOMAIN).
    #[serde(default)]
    pub window_secs: Option<u64>,
    /// Suppress repeat `(rule, src)` alerts within this many milliseconds (0 = off).
    #[serde(default)]
    pub alert_cooldown_ms: Option<u64>,
    #[serde(default)]
    pub thresholds: RuleThresholds,
    /// Rare destination ports. Mode controlled by `rare_ports_mode`.
    #[serde(default)]
    pub rare_ports: Option<Vec<u16>>,
    /// `replace` (default) or `merge` with built-in rare ports.
    #[serde(default = "default_rare_mode")]
    pub rare_ports_mode: String,
    /// Rule ids that must not fire (e.g. `tls_legacy_version`).
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Custom predicate rules evaluated per packet.
    #[serde(default)]
    pub custom_rules: Vec<CustomRuleDef>,
}

fn default_rare_mode() -> String {
    "replace".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleThresholds {
    pub syn_scan_ports: Option<usize>,
    pub host_sweep_hosts: Option<usize>,
    pub dns_unique_names: Option<usize>,
    pub dns_long_name: Option<usize>,
    pub icmp_echo_count: Option<usize>,
    pub tcp_rst_count: Option<usize>,
    pub dhcp_discover_count: Option<usize>,
    pub dns_nxdomain_count: Option<usize>,
}

impl RulePack {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read rule pack {}", path.display()))?;
        let pack: Self = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid rule pack YAML {}", path.display()))?;
        pack.validate()?;
        // Fail fast on bad custom expressions at load time.
        let _ = compile_custom_rules(&pack.custom_rules)?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("rule pack name must not be empty");
        }
        let mode = self.rare_ports_mode.to_ascii_lowercase();
        if mode != "replace" && mode != "merge" {
            bail!("rare_ports_mode must be 'replace' or 'merge'");
        }
        if let Some(secs) = self.window_secs {
            if secs == 0 {
                bail!("window_secs must be greater than zero");
            }
        }
        Ok(())
    }

    /// Apply this pack onto a base config (usually `DetectConfig::default()`).
    pub fn apply_to(&self, mut cfg: DetectConfig) -> Result<DetectConfig> {
        if let Some(secs) = self.window_secs {
            cfg.scan_window = Duration::from_secs(secs);
        }
        if let Some(ms) = self.alert_cooldown_ms {
            cfg.alert_cooldown_ms = ms;
        }
        let t = &self.thresholds;
        if let Some(n) = t.syn_scan_ports {
            cfg.syn_scan_ports = n;
        }
        if let Some(n) = t.host_sweep_hosts {
            cfg.host_sweep_hosts = n;
        }
        if let Some(n) = t.dns_unique_names {
            cfg.dns_unique_names = n;
        }
        if let Some(n) = t.dns_long_name {
            cfg.dns_long_name = n;
        }
        if let Some(n) = t.icmp_echo_count {
            cfg.icmp_echo_count = n;
        }
        if let Some(n) = t.tcp_rst_count {
            cfg.tcp_rst_count = n;
        }
        if let Some(n) = t.dhcp_discover_count {
            cfg.dhcp_discover_count = n;
        }
        if let Some(n) = t.dns_nxdomain_count {
            cfg.dns_nxdomain_count = n;
        }

        if let Some(ports) = &self.rare_ports {
            let mode = self.rare_ports_mode.to_ascii_lowercase();
            if mode == "merge" {
                for p in ports {
                    cfg.rare_ports.insert(*p);
                }
            } else {
                cfg.rare_ports = ports.iter().copied().collect();
            }
        }

        cfg.disabled_rules = self
            .disabled_rules
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>();

        cfg.custom_rules = compile_custom_rules(&self.custom_rules)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn loads_and_applies_pack() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
name: lab-strict
description: tighter lab pack
window_secs: 15
alert_cooldown_ms: 1000
thresholds:
  syn_scan_ports: 5
  tcp_rst_count: 10
rare_ports: [31337, 4444]
rare_ports_mode: replace
disabled_rules: [tls_legacy_version]
custom_rules:
  - id: ssh_alt_port
    severity: medium
    once: per_src
    detail: "SSH on port {{tcp.dst_port}}"
    when:
      and:
        - field: app
          eq: ssh
        - field: tcp.dst_port
          not_in: [22]
"#
        )
        .unwrap();

        let pack = RulePack::load(f.path()).unwrap();
        assert_eq!(pack.name, "lab-strict");
        assert_eq!(pack.custom_rules.len(), 1);
        let cfg = pack.apply_to(DetectConfig::default()).unwrap();
        assert_eq!(cfg.syn_scan_ports, 5);
        assert_eq!(cfg.tcp_rst_count, 10);
        assert_eq!(cfg.scan_window, Duration::from_secs(15));
        assert_eq!(cfg.alert_cooldown_ms, 1000);
        assert!(cfg.rare_ports.contains(&31337));
        assert!(!cfg.rare_ports.contains(&12345));
        assert!(cfg.rule_enabled("tcp_syn_scan"));
        assert!(!cfg.rule_enabled("tls_legacy_version"));
        assert_eq!(cfg.custom_rules.len(), 1);
        assert_eq!(cfg.custom_rules[0].id, "ssh_alt_port");
    }
}
