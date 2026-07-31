# Changelog

## 0.30.0 - 2026-07-31

### Added
- Offline `-f` / `--filter` without `--features live` (software tcpdump-like subset)
- Protocols: `ip`/`ip6`/`arp`/`tcp`/`udp`/`icmp`/`icmp6`; `port`/`portrange`/`host`/`net` with optional `src`/`dst`
- Combinators: `and`/`or`/`not`, `&&`/`||`/`!`, parentheses (e.g. `udp port 53`, `tcp and not arp`)
- Live capture still uses full libpcap/Npcap BPF when built with `--features live`

## 0.29.0 - 2026-07-31

### Added
- Capture `-e` / `--link`: print Ethernet/link-level headers on each packet line (tcpdump-style)
- Shows MACs, ethertype name (`IPv4`/`IPv6`/`ARP`/…), optional VLAN, and frame length

## 0.28.0 - 2026-07-31

### Added
- JA3S TLS ServerHello fingerprints (`tls.ja3s` string + `tls.ja3s_hash` MD5)
- Capture summary / `-vv` shows JA3S hash; custom-rule fields `tls.ja3s` / `tls.ja3s_hash`
- Example custom rule `tls_ja3s_present` in `examples/rules.lab.yaml`

## 0.27.0 - 2026-07-31

### Added
- JA3 TLS ClientHello fingerprints (`tls.ja3` string + `tls.ja3_hash` MD5)
- GREASE filtering for ciphers / extensions / supported groups
- Capture summary / `-vv` shows JA3 hash; custom-rule fields `tls.ja3` / `tls.ja3_hash`
- Example custom rule `tls_ja3_present` in `examples/rules.lab.yaml`

## 0.26.0 - 2026-07-31

### Added
- Zeek `weird.log` import (`import --zeek-weird`) for TSV (`#fields`) and JSONL
- Rule ids `zeek:weird:{name}` with low/medium severity heuristics
- Optional `--weird-names` filter (comma-separated; empty = all)
- Sample: `examples/weird.sample.log`
- Module catalog entry `import/zeek_weird`

## 0.25.0 - 2026-07-31

### Added
- `diff` command: compare two detect-compatible alert JSON reports (`--before` / `--after`)
- Fingerprint modes via `--key`: `full` (default), `rule-src`, `rule`
- Multiset counting (duplicate alerts handled)
- Optional `--json-out` structured diff + `--fail-on-diff` for CI gates
- Audit trail for diff runs

## 0.24.0 - 2026-07-31

### Added
- Capture payload dumps: `-A` / `--ascii` (tcpdump-style ASCII) and `-X` / `--hex` (hex + ASCII)
- `-X` takes precedence when both flags are set
- Unit tests for dump formatters

## 0.23.0 - 2026-07-31

### Added
- Offline **PCAPNG** read support (`-r` / `OfflineSource`) — Section Header, Interface Description, Enhanced Packet, Simple Packet blocks
- Auto-detect classical PCAP vs PCAPNG by file magic
- Timestamp resolution via IDB `if_tsresol` (default microseconds)
- Fixture: `tests/fixtures/dns_query.pcapng`

### Notes
- `-w` still writes classical PCAP only

## 0.22.0 - 2026-07-31

### Added
- Zeek `notice.log` import (`import --zeek`) for TSV (`#fields`) and JSONL
- Rule ids `zeek:notice:{Note::Type}` with heuristic severity mapping
- Optional `--note-types` filter (comma-separated; empty = all)
- Detect-compatible `--json-out` + SIEM re-export (same as EVE import)
- Sample: `examples/notice.sample.log`

## 0.21.0 - 2026-07-31

### Added
- Session presence panel on live `watch` dashboard (TUI + HTML/`/api/snapshot`)
- Operators show `active` / `stale` / `left` with last-seen ages
- Recent shared notes surface on the dashboard when `--session-dir` is attached
- Presence refreshes on paint and after heartbeat

## 0.20.0 - 2026-07-31

### Added
- Multi-operator engagement sessions (`session create|join|heartbeat|leave|status|note`)
- Scope-ticket authentication: join requires matching `ticket_id` (+ optional operator allowlist)
- Shared session directory: `session.json`, `notes.jsonl`, `alerts.jsonl`
- `detect` / `watch --session-dir` attach + stream alerts into the session
- Watch heartbeat every 30s while attached

## 0.19.0 - 2026-07-31

### Added
- Suricata EVE JSONL import (`import --eve`)
- Converts `alert` (and optional other) events into Devil Eye alerts
- Detect-compatible `--json-out` for `report --detect-json`
- Optional SIEM re-export (`--siem-out` / `--siem-udp`)
- Filters: `--event-types`, `--max-alerts`
- Sample: `examples/eve.sample.jsonl`

## 0.18.0 - 2026-07-31

### Added
- SIEM alert export: `jsonl`, `cef`, and `syslog` formats
- Streaming export on `detect` / `watch` via `--siem-out`, `--siem-format`, `--siem-udp`
- Offline `export` command: convert detect JSON reports to SIEM lines
- Events stamp ticket/operator/module/hostname for SIEM correlation

## 0.17.0 - 2026-07-31

### Added
- Correlation windows for custom rules (`correlate:` in YAML packs)
- `window_secs` + `track` (`by_src` / `by_dst` / `by_pair` / `global`)
- Thresholds: `count` and/or `unique_field` + `unique_count`
- Detail placeholders `{count}`, `{unique}`, `{window_secs}`
- Windows use packet timestamps (correct for offline PCAP replay)
- Example correlated rules in `examples/rules.lab.yaml`

## 0.16.0 - 2026-07-31

### Added
- Custom rule expressions in YAML packs (`custom_rules`)
- Predicate DSL: `and` / `or` / `not` with field ops (`eq`, `ne`, `gt`/`gte`/`lt`/`lte`, `in`/`not_in`, `contains`, `starts_with`/`ends_with`, `exists`, `in_cidr`/`not_in_cidr`)
- Per-rule `once`: `none` | `once` | `per_src` (default)
- Detail templates with `{field}` placeholders (e.g. `{tcp.dst_port}`, `{tls.sni}`)
- Example custom rules in `examples/rules.lab.yaml`

## 0.15.0 - 2026-07-31

### Added
- `watch` live dashboard: terminal redraw of traffic + IDS alerts
- Optional `--html-out` snapshot file and `--serve host:port` localhost UI
- JSON API at `/api/snapshot` for browser polling
- Flags: `--refresh-ms`, `--recent`, `--no-clear`, `--no-hold`, `-q`

## 0.14.0 - 2026-07-31

### Added
- YAML rule packs for IDS-lite (`detect --rules`)
- Pack fields: thresholds, window_secs, rare_ports (+ merge/replace), disabled_rules
- Example pack: `examples/rules.lab.yaml`
- CLI flags still override pack values when both are set

## 0.13.0 - 2026-07-31

### Added
- PCAP packet timeline: fixed-width activity buckets (tcp/udp/app counts)
- Capture time range + peak bucket in Markdown/HTML/JSON reports
- Engagement timeline events for PCAP start / peak / end
- CLI: `report --pcap-timeline-buckets N` (default 24)

## 0.12.0 - 2026-07-31

### Added
- Detect: `arp_mac_conflict`, `tcp_rst_burst`, `http_cleartext_auth`
- Detect: `tls_legacy_version`, `dhcp_discover_flood`, `dns_nxdomain_burst`
- CLI thresholds: `--tcp-rst-count`, `--dhcp-discover-count`, `--dns-nxdomain-count`
- HTTP decode flags presence of Authorization without storing credentials

## 0.11.0 - 2026-07-31

### Added
- Report export templates: `full` (default), `executive`, `compact`
- CLI: `report --template <name>` for Markdown/HTML layouts

## 0.10.0 - 2026-07-31

### Added
- Passive ARP decode (Ethernet/IPv4 request & reply)
- Passive DHCP decode (message type, xid, chaddr, hostname, key options)
- Capture stats / PCAP summary / charts include ARP and DHCP

## 0.9.0 - 2026-07-31

### Added
- Engagement timeline: merged audit + alerts + module milestones
- Markdown timeline table; HTML timeline rail (SVG) + vertical event list
- Timeline included in JSON evidence packs

## 0.8.0 - 2026-07-31

### Added
- Passive SSH identification-string decode (`SSH-2.0-…` banners)
- Passive TLS handshake metadata: ClientHello SNI, ServerHello cipher (no decryption)
- Capture stats / PCAP report summary counters for SSH and TLS

## 0.7.0 - 2026-07-31

### Added
- HTML evidence packs: KPI strip + offline SVG bar charts
- Charts for capture protocol mix, alert severity/rules, connect-scan open vs closed

## 0.6.0 - 2026-07-31

### Added
- Detect rules: `tcp_null_scan`, `tcp_fin_scan`, `tcp_xmas_scan`
- Detect rules: `tcp_host_sweep`, `icmp_echo_flood`
- CLI: `--host-sweep-hosts`, `--icmp-echo-count`

## 0.5.0 - 2026-07-31

### Added
- `report` module: Markdown / HTML / JSON engagement evidence packs
- Optional PCAP summary and audit-trail inclusion in reports
- CI workflows (fmt, clippy, test) and tagged release packaging
- Windows local packaging script (`scripts/package-windows.ps1`)

## 0.4.0 - 2026-07-31

### Added
- `detect` IDS-lite: SYN scan, rare ports, DNS long-name / volume alerts
- Offline PCAP and live capture sources for detection

## 0.3.0 - 2026-07-31

### Added
- `enum` module: HTTP/SSH/raw banners + TLS certificate metadata
- Scope-gated enumeration with audit logging

## 0.2.0 - 2026-07-31

### Added
- Subcommand CLI (`capture`, `scan`, `modules`)
- Authorization scope JSON + append-only audit log
- TCP connect scan auxiliary module

## 0.1.0 - 2026-07-30

### Added
- Initial tcpdump-class capture / decode / PCAP / stats MVP
- Optional `--features live` Npcap/libpcap backend
