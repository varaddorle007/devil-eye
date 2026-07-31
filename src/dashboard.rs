//! Live operator dashboard: terminal redraw + optional localhost HTML/API.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::detect::Alert;
use crate::session::SessionDashInfo;
use crate::stats::StatsSnapshot;

/// Rolling live view consumed by terminal + HTTP surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct DashSnapshot {
    pub module: String,
    pub source: String,
    pub rules_pack: Option<String>,
    pub elapsed_secs: f64,
    pub packets_per_sec: f64,
    pub traffic: StatsSnapshot,
    pub alert_total: usize,
    pub alerts_by_severity: Vec<CountRow>,
    pub alerts_by_rule: Vec<CountRow>,
    pub recent_alerts: Vec<Alert>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionDashInfo>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CountRow {
    pub key: String,
    pub count: u64,
}

/// Mutable dashboard state updated by the capture loop.
#[derive(Debug)]
pub struct DashState {
    pub started: Instant,
    pub source_label: String,
    pub rules_pack: Option<String>,
    pub traffic: StatsSnapshot,
    pub alerts: Vec<Alert>,
    pub recent_limit: usize,
    pub status: String,
    pub session: Option<SessionDashInfo>,
    last_packets: u64,
    last_tick: Instant,
    packets_per_sec: f64,
}

impl DashState {
    pub fn new(source_label: String, rules_pack: Option<String>, recent_limit: usize) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            source_label,
            rules_pack,
            traffic: StatsSnapshot::default(),
            alerts: Vec::new(),
            recent_limit: recent_limit.max(1),
            status: "running".into(),
            session: None,
            last_packets: 0,
            last_tick: now,
            packets_per_sec: 0.0,
        }
    }

    pub fn update_traffic(&mut self, traffic: StatsSnapshot) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f64();
        if dt >= 0.2 {
            let delta = traffic.packets.saturating_sub(self.last_packets) as f64;
            self.packets_per_sec = delta / dt;
            self.last_packets = traffic.packets;
            self.last_tick = now;
        }
        self.traffic = traffic;
    }

    pub fn push_alerts(&mut self, new_alerts: &[Alert]) {
        self.alerts.extend(new_alerts.iter().cloned());
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    pub fn set_session(&mut self, session: Option<SessionDashInfo>) {
        self.session = session;
    }

    pub fn snapshot(&self) -> DashSnapshot {
        let mut by_sev: HashMap<String, u64> = HashMap::new();
        let mut by_rule: HashMap<String, u64> = HashMap::new();
        for a in &self.alerts {
            *by_sev.entry(a.severity.clone()).or_insert(0) += 1;
            *by_rule.entry(a.rule.clone()).or_insert(0) += 1;
        }
        let mut alerts_by_severity: Vec<_> = by_sev
            .into_iter()
            .map(|(key, count)| CountRow { key, count })
            .collect();
        alerts_by_severity.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        let mut alerts_by_rule: Vec<_> = by_rule
            .into_iter()
            .map(|(key, count)| CountRow { key, count })
            .collect();
        alerts_by_rule.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));

        let recent_alerts: Vec<Alert> = self
            .alerts
            .iter()
            .rev()
            .take(self.recent_limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        DashSnapshot {
            module: "watch/dashboard".into(),
            source: self.source_label.clone(),
            rules_pack: self.rules_pack.clone(),
            elapsed_secs: self.started.elapsed().as_secs_f64(),
            packets_per_sec: self.packets_per_sec,
            traffic: self.traffic.clone(),
            alert_total: self.alerts.len(),
            alerts_by_severity,
            alerts_by_rule,
            recent_alerts,
            status: self.status.clone(),
            session: self.session.clone(),
        }
    }
}

/// Render a terminal-friendly dashboard panel.
pub fn render_terminal(snap: &DashSnapshot) -> String {
    let mut out = String::new();
    out.push_str("Devil Eye — live dashboard (authorized use only)\n");
    out.push_str("------------------------------------------------\n");
    out.push_str(&format!(
        "status={:<10} source={}  pack={}\n",
        snap.status,
        snap.source,
        snap.rules_pack.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "elapsed={:.1}s  pps={:.1}  packets={}  bytes={}  alerts={}\n",
        snap.elapsed_secs,
        snap.packets_per_sec,
        snap.traffic.packets,
        snap.traffic.bytes,
        snap.alert_total
    ));
    out.push_str(&format!(
        "proto  tcp={} udp={} icmp={} dns={} http={} ssh={} tls={} arp={} dhcp={}\n",
        snap.traffic.tcp,
        snap.traffic.udp,
        snap.traffic.icmp,
        snap.traffic.dns,
        snap.traffic.http,
        snap.traffic.ssh,
        snap.traffic.tls,
        snap.traffic.arp,
        snap.traffic.dhcp
    ));

    if !snap.alerts_by_severity.is_empty() {
        out.push_str("severity: ");
        let parts: Vec<_> = snap
            .alerts_by_severity
            .iter()
            .map(|r| format!("{}={}", r.key, r.count))
            .collect();
        out.push_str(&parts.join("  "));
        out.push('\n');
    }

    if !snap.alerts_by_rule.is_empty() {
        out.push_str("rules: ");
        let parts: Vec<_> = snap
            .alerts_by_rule
            .iter()
            .take(8)
            .map(|r| format!("{}={}", r.key, r.count))
            .collect();
        out.push_str(&parts.join("  "));
        out.push('\n');
    }

    if !snap.traffic.top_dst_ports.is_empty() {
        out.push_str("top dst ports: ");
        let parts: Vec<_> = snap
            .traffic
            .top_dst_ports
            .iter()
            .take(6)
            .map(|p| format!("{}:{}", p.port, p.count))
            .collect();
        out.push_str(&parts.join("  "));
        out.push('\n');
    }

    if let Some(sess) = &snap.session {
        let title = if sess.title.is_empty() {
            "-"
        } else {
            sess.title.as_str()
        };
        out.push_str(&format!(
            "session {}  ticket={}  title={}  active_ops={}/{}\n",
            sess.session_id,
            sess.ticket_id,
            title,
            sess.active_operators,
            sess.operators.len()
        ));
        out.push_str(&format!(
            "shared notes={}  shared alerts={}\n",
            sess.notes_count, sess.shared_alerts_count
        ));
        out.push_str("operators:\n");
        for op in &sess.operators {
            out.push_str(&format!(
                "  - {} [{role}] {live} ({ago}s ago)\n",
                op.name,
                role = op.role,
                live = op.live,
                ago = op.last_seen_secs_ago
            ));
        }
        if !sess.recent_notes.is_empty() {
            out.push_str("recent notes:\n");
            for n in sess.recent_notes.iter().rev().take(3) {
                out.push_str(&format!("  - {}: {}\n", n.operator, n.text));
            }
        }
    }

    out.push_str("recent alerts:\n");
    if snap.recent_alerts.is_empty() {
        out.push_str("  (none yet)\n");
    } else {
        for a in snap.recent_alerts.iter().rev() {
            out.push_str(&format!(
                "  [{:<8}] {:<22} src={} — {}\n",
                a.severity, a.rule, a.src, a.detail
            ));
        }
    }
    out.push_str("Ctrl+C to stop\n");
    out
}

/// Write dashboard to stdout, optionally clearing the screen first.
pub fn paint_terminal(snap: &DashSnapshot, clear: bool) -> Result<()> {
    let body = render_terminal(snap);
    let mut out = std::io::stdout().lock();
    if clear {
        write!(out, "\x1B[2J\x1B[H")?;
    } else {
        writeln!(out)?;
    }
    write!(out, "{body}")?;
    out.flush()?;
    Ok(())
}

/// Self-contained HTML page with client-side polling of `/api/snapshot`.
pub fn render_html_page(poll_ms: u64) -> String {
    let poll = poll_ms.max(200);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Devil Eye — live dashboard</title>
<style>
  :root {{
    --bg: #0f1419;
    --panel: #1a222c;
    --text: #e7ecf1;
    --muted: #8b9aab;
    --accent: #c45c26;
    --ok: #3d9a6a;
    --warn: #c9a227;
    --high: #c94c4c;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
    background: radial-gradient(1200px 600px at 10% -10%, #243041 0%, var(--bg) 55%);
    color: var(--text); min-height: 100vh; padding: 1.5rem;
  }}
  h1 {{ font-family: "IBM Plex Serif", Georgia, serif; font-weight: 600; margin: 0 0 .25rem;
       font-size: clamp(1.6rem, 3vw, 2.2rem); letter-spacing: .02em; }}
  .sub {{ color: var(--muted); margin-bottom: 1.25rem; }}
  .grid {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }}
  .kpi {{ background: var(--panel); padding: .9rem 1rem; border-left: 3px solid var(--accent); }}
  .kpi .n {{ font-size: 1.5rem; font-variant-numeric: tabular-nums; }}
  .kpi .l {{ color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; }}
  section {{ margin-top: 1.25rem; }}
  h2 {{ font-size: 1rem; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
  th, td {{ text-align: left; padding: .45rem .35rem; border-bottom: 1px solid #2a3440; }}
  th {{ color: var(--muted); font-weight: 500; }}
  .sev-high {{ color: var(--high); }}
  .sev-medium {{ color: var(--warn); }}
  .sev-low {{ color: var(--ok); }}
  #status {{ font-weight: 600; }}
  .live-active {{ color: var(--ok); }}
  .live-stale {{ color: var(--warn); }}
  .live-left {{ color: var(--muted); }}
  #session {{ display: none; }}
  #session.visible {{ display: block; }}
  .ops {{ list-style: none; padding: 0; margin: .4rem 0 0; }}
  .ops li {{ padding: .25rem 0; border-bottom: 1px solid #2a3440; }}
  .notes {{ color: var(--muted); font-size: .9rem; margin: .5rem 0 0; }}
</style>
</head>
<body>
  <h1>Devil Eye</h1>
  <p class="sub">Live dashboard · authorized observation only · <span id="status">connecting…</span></p>
  <div class="grid" id="kpis"></div>
  <section>
    <h2>Protocol mix</h2>
    <div id="proto"></div>
  </section>
  <section id="session">
    <h2>Session presence</h2>
    <p id="sess-meta" class="sub" style="margin-bottom:.5rem"></p>
    <ul class="ops" id="ops"></ul>
    <div class="notes" id="notes"></div>
  </section>
  <section>
    <h2>Recent alerts</h2>
    <table>
      <thead><tr><th>Sev</th><th>Rule</th><th>Src</th><th>Detail</th></tr></thead>
      <tbody id="alerts"></tbody>
    </table>
  </section>
<script>
async function tick() {{
  try {{
    const r = await fetch('/api/snapshot');
    const s = await r.json();
    document.getElementById('status').textContent = s.status + ' · ' + s.source;
    document.getElementById('kpis').innerHTML = [
      kpi('Packets', s.traffic.packets),
      kpi('Bytes', s.traffic.bytes),
      kpi('PPS', Number(s.packets_per_sec).toFixed(1)),
      kpi('Alerts', s.alert_total),
      kpi('Elapsed', Number(s.elapsed_secs).toFixed(1) + 's'),
    ].join('');
    const t = s.traffic;
    document.getElementById('proto').textContent =
      `tcp=${{t.tcp}}  udp=${{t.udp}}  icmp=${{t.icmp}}  dns=${{t.dns}}  http=${{t.http}}  ssh=${{t.ssh}}  tls=${{t.tls}}  arp=${{t.arp}}  dhcp=${{t.dhcp}}`;
    const sessEl = document.getElementById('session');
    if (s.session) {{
      const sess = s.session;
      sessEl.classList.add('visible');
      const title = sess.title ? ' · ' + esc(sess.title) : '';
      document.getElementById('sess-meta').innerHTML =
        `id ${{esc(sess.session_id)}} · ticket ${{esc(sess.ticket_id)}}${{title}} · active ${{sess.active_operators}}/${{(sess.operators||[]).length}} · notes ${{sess.notes_count}} · shared alerts ${{sess.shared_alerts_count}}`;
      document.getElementById('ops').innerHTML = (sess.operators || []).map(op =>
        `<li><span class="live-${{esc(op.live)}}">${{esc(op.live)}}</span> · <strong>${{esc(op.name)}}</strong> [${{esc(op.role)}}] · ${{op.last_seen_secs_ago}}s ago</li>`
      ).join('') || '<li>(no operators)</li>';
      const notes = (sess.recent_notes || []).slice().reverse().slice(0, 3);
      document.getElementById('notes').innerHTML = notes.length
        ? notes.map(n => `<div>${{esc(n.operator)}}: ${{esc(n.text)}}</div>`).join('')
        : '';
    }} else {{
      sessEl.classList.remove('visible');
    }}
    const rows = (s.recent_alerts || []).slice().reverse().map(a => {{
      const cls = 'sev-' + (a.severity || '').toLowerCase();
      return `<tr><td class="${{cls}}">${{esc(a.severity)}}</td><td>${{esc(a.rule)}}</td><td>${{esc(a.src)}}</td><td>${{esc(a.detail)}}</td></tr>`;
    }}).join('') || '<tr><td colspan="4">(none yet)</td></tr>';
    document.getElementById('alerts').innerHTML = rows;
  }} catch (e) {{
    document.getElementById('status').textContent = 'offline';
  }}
}}
function kpi(l, n) {{ return `<div class="kpi"><div class="n">${{n}}</div><div class="l">${{l}}</div></div>`; }}
function esc(x) {{ return String(x ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]); }}
tick();
setInterval(tick, {poll});
</script>
</body>
</html>
"#
    )
}

/// Static HTML snapshot (no live poll) for `--html-out` offline refresh.
pub fn render_html_snapshot(snap: &DashSnapshot) -> String {
    let json = serde_json::to_string(snap).unwrap_or_else(|_| "{}".into());
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta http-equiv="refresh" content="2"/>
<title>Devil Eye — live snapshot</title>
<style>
 body{{font-family:Consolas,monospace;background:#111;color:#eee;padding:1rem}}
 pre{{white-space:pre-wrap}}
</style></head><body>
<h1>Devil Eye live snapshot</h1>
<pre id="t"></pre>
<script>
const s = {json};
document.getElementById('t').textContent = JSON.stringify(s, null, 2);
</script>
</body></html>
"#
    )
}

/// Persist HTML snapshot to disk.
pub fn write_html_file(path: &Path, snap: &DashSnapshot) -> Result<()> {
    let html = render_html_snapshot(snap);
    std::fs::write(path, html).with_context(|| format!("failed to write {}", path.display()))
}

/// Spawn a localhost HTTP server serving `/` and `/api/snapshot`.
pub fn spawn_http_server(
    bind: &str,
    state: Arc<Mutex<DashState>>,
    running: Arc<AtomicBool>,
    poll_ms: u64,
) -> Result<SocketAddr> {
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid --serve address: {bind}"))?;
    let listener = TcpListener::bind(addr).with_context(|| format!("failed to bind {addr}"))?;
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?;
    let page = render_html_page(poll_ms);

    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = handle_http(stream, &state, &page);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(40));
                }
                Err(_) => thread::sleep(Duration::from_millis(40)),
            }
        }
    });

    Ok(local)
}

fn handle_http(mut stream: TcpStream, state: &Arc<Mutex<DashState>>, page: &str) -> Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    let target = line.split_whitespace().nth(1).unwrap_or("/");

    if target.starts_with("/api/snapshot") {
        let snap = state
            .lock()
            .map_err(|_| anyhow::anyhow!("dashboard lock poisoned"))?
            .snapshot();
        let body = serde_json::to_vec(&snap)?;
        write_response(&mut stream, "application/json; charset=utf-8", &body)?;
    } else if target == "/" || target.starts_with("/?") {
        write_response(&mut stream, "text/html; charset=utf-8", page.as_bytes())?;
    } else {
        let body = b"not found";
        let header = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(body)?;
    }
    Ok(())
}

fn write_response(stream: &mut TcpStream, content_type: &str, body: &[u8]) -> Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

/// Parse `--serve` bind string (defaults port if host-only is unlikely; require host:port).
pub fn parse_serve_addr(raw: &str) -> Result<String> {
    if raw.contains(':') {
        Ok(raw.to_string())
    } else {
        bail!("--serve expects host:port (e.g. 127.0.0.1:8787), got {raw}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Alert;
    use crate::stats::StatsSnapshot;

    #[test]
    fn terminal_mentions_alerts() {
        let mut st = DashState::new("pcap:lab.pcap".into(), Some("lab".into()), 5);
        st.update_traffic(StatsSnapshot {
            packets: 10,
            bytes: 500,
            tcp: 8,
            ..Default::default()
        });
        st.push_alerts(&[Alert {
            ts_unix_ms: 1,
            rule: "rare_port".into(),
            severity: "medium".into(),
            src: "1.2.3.4".into(),
            detail: "dst port 4444".into(),
        }]);
        let text = render_terminal(&st.snapshot());
        assert!(text.contains("Devil Eye"));
        assert!(text.contains("rare_port"));
        assert!(text.contains("alerts=1"));
    }

    #[test]
    fn html_page_has_poll() {
        let html = render_html_page(500);
        assert!(html.contains("/api/snapshot"));
        assert!(html.contains("setInterval"));
        assert!(html.contains("Session presence"));
        assert!(html.contains("s.session"));
    }

    #[test]
    fn terminal_shows_session_presence() {
        use crate::session::{SessionDashInfo, SessionNoteView, SessionOpView};
        let mut st = DashState::new("pcap:lab.pcap".into(), None, 5);
        st.set_session(Some(SessionDashInfo {
            session_id: "sess-abc".into(),
            ticket_id: "AUTH-LAB-0001".into(),
            title: "Lab night".into(),
            operators: vec![SessionOpView {
                name: "alice".into(),
                role: "lead".into(),
                live: "active".into(),
                last_seen_secs_ago: 2,
            }],
            active_operators: 1,
            notes_count: 1,
            shared_alerts_count: 0,
            recent_notes: vec![SessionNoteView {
                operator: "alice".into(),
                text: "watching DNS".into(),
                ts_unix_ms: 1,
            }],
        }));
        let text = render_terminal(&st.snapshot());
        assert!(text.contains("session sess-abc"));
        assert!(text.contains("alice"));
        assert!(text.contains("active"));
        assert!(text.contains("watching DNS"));
        let json = serde_json::to_value(st.snapshot()).unwrap();
        assert_eq!(json["session"]["ticket_id"], "AUTH-LAB-0001");
    }
}
