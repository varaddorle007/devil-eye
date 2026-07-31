# Devil Eye

Authorized cybersecurity toolkit:

- **tcpdump-class** passive capture / decode / PCAP / stats
- **Metasploit-style modular CLI** for scoped auxiliary assessment

Devil Eye is **not** a Metasploit clone. It does **not** ship exploit payloads, credential theft, malware, or unauthorized-access automation.

| Project | What Devil Eye takes | What we deliberately skip |
|---------|----------------------|---------------------------|
| [tcpdump](https://github.com/the-tcpdump-group/tcpdump) | Capture, BPF, PCAP, decode, CLI UX | Full protocol printer zoo |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Modular commands, auxiliary scanners, reporting, operator workflow | Exploits, payloads, post-exploitation |

## Authorized use only

Use only on networks you **own** or have **written authorization** to test/monitor. Active modules refuse to run without a scope file where `authorized: true`. Every run appends an audit log.

## Architecture

```
devil-eye capture   → passive (tcpdump-like)
devil-eye detect    → IDS-lite on PCAP/live
devil-eye watch     → live dashboard (terminal / HTML)
devil-eye diff      → compare detect alert JSON reports
devil-eye scan      → auxiliary TCP connect scan (scope REQUIRED)
devil-eye modules   → catalog (passive + auxiliary only)
```

## Quick start

```powershell
cargo build --release

# List modules
.\target\release\devil-eye.exe modules

# Passive capture / PCAP replay
.\target\release\devil-eye.exe capture -r tests\fixtures\dns_query.pcap --stats
.\target\release\devil-eye.exe capture -r tests\fixtures\mixed.pcap -f "udp port 53"
.\target\release\devil-eye.exe capture -r tests\fixtures\http_get.pcap -c 1 -X

# Authorized connect scan (edit examples\scope.lab.json first)
.\target\release\devil-eye.exe scan --scope examples\scope.lab.json --json-out scan-report.json

# Authorized banners + TLS cert metadata (handshake certs only — not session decryption)
.\target\release\devil-eye.exe enum --scope examples\scope.lab.json --json-out enum-report.json

# IDS-lite over a PCAP
.\target\release\devil-eye.exe detect -r capture.pcap --json-out alerts.json --rules examples\rules.lab.yaml

# Stream alerts to SIEM (JSONL file); offline CEF conversion
.\target\release\devil-eye.exe detect -r capture.pcap --siem-out alerts.jsonl --siem-format jsonl
.\target\release\devil-eye.exe export --detect-json alerts.json --siem-out alerts.cef --siem-format cef

# Import Suricata EVE or Zeek notice.log into Devil Eye / report / SIEM
.\target\release\devil-eye.exe import --eve examples\eve.sample.jsonl --json-out eve-alerts.json -v
.\target\release\devil-eye.exe import --zeek examples\notice.sample.log --json-out zeek-alerts.json -v
.\target\release\devil-eye.exe import --zeek-weird examples\weird.sample.log --json-out weird-alerts.json -v
.\target\release\devil-eye.exe report --detect-json eve-alerts.json --out-md eve-report.md --template executive
.\target\release\devil-eye.exe diff --before baseline-alerts.json --after eve-alerts.json --json-out delta.json

# Multi-operator session (shared folder + matching scope ticket)
.\target\release\devil-eye.exe session create --scope examples\scope.lab.json --session-dir .\sessions\lab1 --title "Lab capture"
.\target\release\devil-eye.exe session join --scope examples\scope.lab.json --session-dir .\sessions\lab1 --role observer
.\target\release\devil-eye.exe detect -r capture.pcap --scope examples\scope.lab.json --session-dir .\sessions\lab1

# Live dashboard (terminal; optional HTML file + localhost API)
.\target\release\devil-eye.exe watch -r capture.pcap --rules examples\rules.lab.yaml --no-clear
.\target\release\devil-eye.exe watch -r capture.pcap --html-out live.html --serve 127.0.0.1:8787 --no-hold

# Assemble evidence pack (Markdown + HTML)
.\target\release\devil-eye.exe report --scope examples\scope.lab.json --pcap tests\fixtures\dns_query.pcap --detect-json alerts.json --out-md report.md --out-html report.html --template executive --note "Lab engagement only"
```

## Scope file (required for active modules)

See [`examples/scope.lab.json`](examples/scope.lab.json):

- `ticket_id`, `operator`, `authorized: true`
- `targets` — IPs or CIDRs
- `exclude` — never-touch ranges
- `ports`, `max_pps`, `max_hosts`, optional `valid_until_unix`

## Live capture on Windows (Npcap)

1. Install [Npcap](https://npcap.com/) (+ SDK to build with live support).
2. Point the linker at the SDK libs:

```powershell
$env:LIB = "$env:USERPROFILE\npcap-sdk\Lib\x64;$env:LIB"
# or: C:\Program Files\Npcap\SDK\Lib\x64
cargo build --release --features live
```

3. Elevated terminal:

```powershell
.\target\release\devil-eye.exe capture -D
.\target\release\devil-eye.exe capture -i "\Device\NPF_{GUID}" -f "tcp port 443" -c 50
.\target\release\devil-eye.exe capture -i "\Device\NPF_Loopback" -f "udp port 53" --stats
```

Without `--features live`, live `-i`/`-D` print install instructions. Offline `-r` and software `-f` still work.

## CLI cheat sheet

### `capture` (passive)

| Flag | Meaning |
|------|---------|
| `-D` | List interfaces |
| `-i` | Live interface |
| `-r` / `-w` | Read PCAP or PCAPNG / write classical PCAP |
| `-c` | Packet count |
| `-f` | Filter (offline subset always; full BPF on live) |
| `-v` / `-q` / `--stats` | Verbosity / quiet / stats |
| `-A` / `-X` | ASCII dump / hex+ASCII dump (tcpdump-style) |
| `-e` / `--link` | Print Ethernet/link headers on each line |
| `--scope` | Optional governance scope (logged) |
| `--audit-log` | JSONL audit path |

### `scan` / `enum` (auxiliary)

| Flag | Meaning |
|------|---------|
| `--scope` | **Required** authorization JSON |
| `--audit-log` | JSONL audit path |
| `--json-out` | Write report JSON |
| `--tls-ports` | Extra TLS ports for `enum` (default 443,8443,9443) |
| `-v` | Verbose |

### `detect` (passive IDS-lite)

| Flag | Meaning |
|------|---------|
| `-r` / `-i` | PCAP/PCAPNG file or live interface |
| `-f` | Filter (offline subset always; full BPF on live) |
| `-c` | Packet limit |
| `--rules` | YAML rule pack (see `examples/rules.lab.yaml`) |
| `--syn-scan-ports` | Distinct SYN dest-port threshold |
| `--host-sweep-hosts` | Distinct SYN dest-host threshold |
| `--icmp-echo-count` | ICMP echo-request flood threshold |
| `--tcp-rst-count` | TCP RST burst threshold |
| `--dhcp-discover-count` | DHCP discover flood threshold |
| `--dns-nxdomain-count` | NXDOMAIN response burst threshold |
| `--dns-unique-names` | Unique DNS QNAME volume threshold |
| `--json-out` | Alert report JSON |
| `--siem-out` / `--siem-format` / `--siem-udp` | Stream alerts to SIEM |
| `--session-dir` | Attach multi-operator session (requires `--scope`) |
| `--session-role` | Auto-join role (default `operator`) |
| `--scope` | Optional governance identity |
| `--audit-log` | JSONL audit path |

Rules: `tcp_syn_scan`, `tcp_host_sweep`, `tcp_null_scan`, `tcp_fin_scan`, `tcp_xmas_scan`, `tcp_rst_burst`, `rare_port`, `dns_long_name`, `dns_query_volume`, `dns_nxdomain_burst`, `icmp_echo_flood`, `arp_mac_conflict`, `http_cleartext_auth`, `tls_legacy_version`, `dhcp_discover_flood`, plus any `custom_rules` ids from a YAML pack.

### Custom rule expressions

YAML packs may define `custom_rules` — safe predicate trees (no scripts):

```yaml
custom_rules:
  - id: ssh_alt_port
    severity: medium
    once: per_src          # none | once | per_src
    detail: "SSH on {tcp.dst_port}"
    when:
      and:
        - field: app
          eq: ssh
        - field: tcp.dst_port
          not_in: [22]
```

Operators (exactly one per predicate): `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `contains`, `starts_with`, `ends_with`, `exists`, `in_cidr`, `not_in_cidr`.

Compose with `and` / `or` / `not`. Useful fields include `ip.src`/`ip.dst`, `tcp.*`, `udp.*`, `app`, `dns.*`, `http.*`, `tls.sni` / `tls.ja3` / `tls.ja3_hash` / `tls.ja3s` / `tls.ja3s_hash`, `ssh.*`, `arp.*`, `dhcp.*`.

Optional **correlation windows** (Suricata-style thresholds; uses packet timestamps):

```yaml
  - id: syn_burst_http
    severity: high
    once: per_src
    detail: "{count} SYNs to 80 from {ip.src} in {window_secs}s"
    correlate:
      window_secs: 15
      track: by_src          # by_src | by_dst | by_pair | global
      count: 20              # and/or unique_field + unique_count
    when:
      and:
        - field: tcp.flags.syn
          eq: true
        - field: tcp.dst_port
          eq: 80
```

### `watch` (live dashboard)

| Flag | Meaning |
|------|---------|
| `-r` / `-i` | PCAP/PCAPNG file or live interface |
| `-f` / `-c` | Filter (offline subset / live BPF) / packet limit |
| `--rules` + detect thresholds | Same IDS-lite knobs as `detect` |
| `--refresh-ms` | Terminal / HTML refresh interval (default 500) |
| `--html-out` | Refresh a snapshot HTML file |
| `--serve` | Localhost HTML + `/api/snapshot` JSON (e.g. `127.0.0.1:8787`) |
| `--recent` | Recent alerts kept on the board (default 12) |
| `--no-clear` | Append redraws instead of clearing the terminal |
| `-q` / `--quiet` | Suppress terminal board (HTTP/HTML still update) |
| `--no-hold` | Exit at PCAP EOF even when `--serve` is set |
| `--json-out` | Final dashboard JSON snapshot |
| `--siem-out` / `--siem-format` / `--siem-udp` | Same SIEM streaming as `detect` |
| `--scope` / `--audit-log` | Governance identity + audit trail |

### `export` (SIEM conversion)

| Flag | Meaning |
|------|---------|
| `--detect-json` | Detect module JSON (`detect --json-out`) |
| `--siem-out` | Write SIEM lines to file |
| `--siem-format` | `jsonl` (default), `cef`, `syslog` |
| `--siem-udp` | Optional UDP destination (`host:port`) |
| `--scope` | Optional ticket/operator stamp |
| `--audit-log` | Audit this export run |

### `import` (Suricata EVE / Zeek notice / weird)

| Flag | Meaning |
|------|---------|
| `--eve` | Suricata `eve.json` / JSONL path (xor Zeek flags) |
| `--zeek` | Zeek `notice.log` — TSV with `#fields` or JSONL |
| `--zeek-weird` | Zeek `weird.log` — TSV with `#fields` or JSONL |
| `--json-out` | Detect-compatible alert JSON (for `report`) |
| `--event-types` | Suricata: comma list (default `alert`; also `anomaly`, …) |
| `--note-types` | Zeek notice: comma list of `note` values (empty = all) |
| `--weird-names` | Zeek weird: comma list of `name` values (empty = all) |
| `--max-alerts` | Cap converted alerts (default 100000) |
| `--siem-out` / `--siem-format` / `--siem-udp` | Optional SIEM re-export |
| `--scope` / `--audit-log` | Governance stamp + audit |
| `-v` | Print first converted alerts |

Suricata `alert.severity` maps as 1→high, 2→medium, 3→low. Rule ids become `suricata:{gid}:{signature_id}`.

Zeek notice rule ids become `zeek:notice:{Note::Type}`. Severity is heuristic from the note name (e.g. `Scan::*` / password guessing → high, `DNS::NXDomain` → low).

Zeek weird rule ids become `zeek:weird:{name}` (typically low severity; overflow/checksum-class names → medium).

### `diff` (alert report compare)

Compare two detect-compatible JSON reports (`detect` / `import` / `watch --json-out`).

| Flag | Meaning |
|------|---------|
| `--before` / `--after` | Baseline and newer alert JSON (**required**) |
| `--key` | Fingerprint: `full` (default), `rule-src`, `rule` |
| `--json-out` | Structured diff JSON |
| `--fail-on-diff` | Non-zero exit if any gone/new alerts |
| `--scope` / `--audit-log` | Governance stamp + audit |

Timestamps are ignored; duplicates are counted as a multiset. Use `--key rule-src` when detail text drifts between runs.

### `session` (multi-operator)

Shared engagement directory authenticated by scope `ticket_id` (and optional `--allow` operator list).

| Subcommand | Meaning |
|------------|---------|
| `create` | Create `--session-dir` (caller becomes lead) |
| `join` | Join / re-join with `--role` operator\|observer |
| `heartbeat` | Refresh presence |
| `leave` | Mark yourself left |
| `status` | List operators + note/alert counts |
| `note` | Append a shared operator note |

`detect` / `watch` accept `--session-dir` + `--scope` to attach and append alerts to `alerts.jsonl`. On `watch`, the live dashboard (TUI + HTML/`/api/snapshot`) shows a session presence panel: operators (`active`/`stale`/`left`), note/alert counts, and recent notes.

### `report` (evidence pack)

| Flag | Meaning |
|------|---------|
| `--scope` | Optional scope (ticket/operator/targets) |
| `--scan-json` / `--enum-json` / `--detect-json` | Prior module JSON outputs |
| `--pcap` | Optional PCAP to summarize |
| `--pcap-timeline-buckets` | Packet timeline buckets (default 24, max 128) |
| `--audit-in` | Include audit JSONL trail |
| `--note` | Free-form note (repeatable) |
| `--template` | Layout: `full` (default), `executive`, `compact` |
| `--out-md` / `--out-html` / `--out-json` | Output paths (at least one required) |
| `--audit-log` | Audit this report run |

HTML output includes KPI tiles, offline SVG charts (including PCAP packet timeline), and an engagement timeline (audit + alerts + PCAP start/peak/end) when inputs are present. Use `--template executive` for a management summary without raw JSON dumps.

## Roadmap (authorized only)

1. ~~Capture MVP~~ done  
2. ~~Scope + audit + connect scan~~ done  
3. ~~Service banners / TLS cert metadata~~ done  
4. ~~IDS-lite detection rules on PCAP/live~~ done  
5. ~~Reporting (Markdown/HTML evidence packs)~~ done  
6. ~~CI / release packaging~~ done  
7. ~~Expanded detect rules (stealth scans, host sweep, ICMP)~~ done  
8. ~~Richer HTML report charts~~ done  
9. ~~More protocol decode (SSH banners, TLS SNI/handshake meta)~~ done  
10. ~~Report timeline views~~ done  
11. ~~DHCP/ARP decode~~ done  
12. ~~Export templates (full / executive / compact)~~ done  
13. ~~Expanded IDS rules (ARP/HTTP/TLS/DHCP/NXDOMAIN/RST)~~ done  
14. ~~PCAP packet timeline in reports~~ done  
15. ~~YAML rule packs for detect~~ done  
16. ~~Live dashboard (terminal + optional HTML/HTTP)~~ done  
17. ~~Custom rule expressions in YAML packs~~ done  
18. ~~Correlation windows for custom rules~~ done  
19. ~~SIEM / syslog alert export connectors~~ done  
20. ~~Suricata EVE JSONL import~~ done  
21. ~~Authenticated multi-operator sessions~~ done  
22. ~~Session presence on live dashboard~~ done  
23. ~~Zeek notice.log import~~ done  
24. ~~Offline PCAPNG read~~ done  
25. ~~Capture `-A`/`-X` payload dumps~~ done  
26. ~~Alert report diff (`diff`)~~ done  
27. ~~Zeek weird.log import~~ done  
28. ~~JA3 TLS ClientHello fingerprints~~ done  
29. ~~JA3S TLS ServerHello fingerprints~~ done  
30. ~~Capture `-e` link-level headers~~ done  
31. ~~Offline `-f` software filter (no live feature)~~ done  

Further ideas: none queued.

## Development

```powershell
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

### CI / releases

- GitHub Actions: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs fmt + clippy + tests on Linux/Windows/macOS.
- Tag a version (`v0.5.0`) to trigger [`.github/workflows/release.yml`](.github/workflows/release.yml) and attach binaries.
- Local Windows zip:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1
# optional live binary (needs Npcap SDK on LIB):
powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1 -Live
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT
