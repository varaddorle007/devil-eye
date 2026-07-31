//! Multi-operator engagement sessions (shared dir + scope ticket auth).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::detect::Alert;
use crate::scope::Scope;

const SESSION_FILE: &str = "session.json";
const NOTES_FILE: &str = "notes.jsonl";
const ALERTS_FILE: &str = "alerts.jsonl";
const DEFAULT_MAX_OPERATORS: usize = 16;
/// Operators with no heartbeat beyond this are shown as stale.
pub const STALE_SECS: u64 = 120;

/// On-disk session metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub ticket_id: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub title: String,
    pub created_by: String,
    pub created_at_unix_ms: u64,
    #[serde(default = "default_max_ops")]
    pub max_operators: usize,
    /// If non-empty, only these operator names may join.
    #[serde(default)]
    pub allowed_operators: Vec<String>,
    pub operators: Vec<OperatorPresence>,
}

fn default_max_ops() -> usize {
    DEFAULT_MAX_OPERATORS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorPresence {
    pub name: String,
    pub role: String,
    pub joined_at_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNote {
    pub ts_unix_ms: u64,
    pub operator: String,
    pub ticket_id: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionAlertEvent {
    pub ts_unix_ms: u64,
    pub operator: String,
    pub module: String,
    pub alert: Alert,
}

/// Compact session view for live dashboards.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SessionDashInfo {
    pub session_id: String,
    pub ticket_id: String,
    pub title: String,
    pub operators: Vec<SessionOpView>,
    pub active_operators: u64,
    pub notes_count: u64,
    pub shared_alerts_count: u64,
    pub recent_notes: Vec<SessionNoteView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionOpView {
    pub name: String,
    pub role: String,
    /// `active` | `stale` | `left`
    pub live: String,
    pub last_seen_secs_ago: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionNoteView {
    pub operator: String,
    pub text: String,
    pub ts_unix_ms: u64,
}

/// Validate role string.
pub fn parse_role(raw: &str) -> Result<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "lead" => Ok("lead".into()),
        "operator" | "op" => Ok("operator".into()),
        "observer" | "obs" => Ok("observer".into()),
        other => bail!("role must be lead|operator|observer (got {other})"),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn session_path(dir: &Path) -> PathBuf {
    dir.join(SESSION_FILE)
}

/// Create a new session directory bound to a scope ticket.
pub fn create_session(
    dir: &Path,
    scope: &Scope,
    title: &str,
    max_operators: usize,
    allowed_operators: Vec<String>,
) -> Result<SessionState> {
    if max_operators == 0 {
        bail!("max_operators must be > 0");
    }
    if session_path(dir).exists() {
        bail!(
            "session already exists at {} — use join or pick another --session-dir",
            dir.display()
        );
    }
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create session dir {}", dir.display()))?;

    let now = now_ms();
    let session_id = format!("sess-{now}");
    let state = SessionState {
        session_id,
        ticket_id: scope.ticket_id.clone(),
        organization: scope.organization.clone(),
        title: title.trim().to_string(),
        created_by: scope.operator.clone(),
        created_at_unix_ms: now,
        max_operators,
        allowed_operators: allowed_operators
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        operators: vec![OperatorPresence {
            name: scope.operator.clone(),
            role: "lead".into(),
            joined_at_unix_ms: now,
            last_seen_unix_ms: now,
            status: "active".into(),
        }],
    };
    save_session(dir, &state)?;
    Ok(state)
}

/// Load session.json from a directory.
pub fn load_session(dir: &Path) -> Result<SessionState> {
    let path = session_path(dir);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read session {}", path.display()))?;
    let state: SessionState = serde_json::from_str(&raw)
        .with_context(|| format!("invalid session JSON {}", path.display()))?;
    Ok(state)
}

fn save_session(dir: &Path, state: &SessionState) -> Result<()> {
    let path = session_path(dir);
    let tmp = dir.join("session.json.tmp");
    let body = serde_json::to_string_pretty(state)?;
    fs::write(&tmp, body).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("failed to finalize {}", path.display()))?;
    Ok(())
}

fn assert_ticket(scope: &Scope, state: &SessionState) -> Result<()> {
    if scope.ticket_id.trim() != state.ticket_id.trim() {
        bail!(
            "scope ticket '{}' does not match session ticket '{}' — refusing join",
            scope.ticket_id,
            state.ticket_id
        );
    }
    Ok(())
}

fn assert_allowed(scope: &Scope, state: &SessionState) -> Result<()> {
    if state.allowed_operators.is_empty() {
        return Ok(());
    }
    let op = scope.operator.trim();
    let ok = state
        .allowed_operators
        .iter()
        .any(|a| a.eq_ignore_ascii_case(op));
    if !ok {
        bail!(
            "operator '{}' is not on the session allowlist",
            scope.operator
        );
    }
    Ok(())
}

/// Join or re-join an existing session (updates presence).
pub fn join_session(dir: &Path, scope: &Scope, role: &str) -> Result<SessionState> {
    let role = parse_role(role)?;
    let mut state = load_session(dir)?;
    assert_ticket(scope, &state)?;
    assert_allowed(scope, &state)?;

    let now = now_ms();
    let name = scope.operator.clone();
    if let Some(existing) = state
        .operators
        .iter_mut()
        .find(|o| o.name.eq_ignore_ascii_case(&name))
    {
        existing.last_seen_unix_ms = now;
        existing.status = "active".into();
        // Keep original role unless rejoining as lead creator.
        if role == "lead" && existing.name == state.created_by {
            existing.role = "lead".into();
        } else if existing.role != "lead" {
            existing.role = role;
        }
    } else {
        let active = state
            .operators
            .iter()
            .filter(|o| o.status == "active")
            .count();
        if active >= state.max_operators {
            bail!(
                "session full ({}/{} active operators)",
                active,
                state.max_operators
            );
        }
        // Only the creator may claim lead.
        let role = if role == "lead" && name != state.created_by {
            "operator".into()
        } else {
            role
        };
        state.operators.push(OperatorPresence {
            name,
            role,
            joined_at_unix_ms: now,
            last_seen_unix_ms: now,
            status: "active".into(),
        });
    }
    save_session(dir, &state)?;
    Ok(state)
}

/// Refresh last-seen for the scoped operator.
pub fn heartbeat(dir: &Path, scope: &Scope) -> Result<SessionState> {
    let mut state = load_session(dir)?;
    assert_ticket(scope, &state)?;
    let now = now_ms();
    let name = scope.operator.trim();
    let Some(op) = state
        .operators
        .iter_mut()
        .find(|o| o.name.eq_ignore_ascii_case(name))
    else {
        bail!(
            "operator '{}' has not joined this session — run session join first",
            scope.operator
        );
    };
    op.last_seen_unix_ms = now;
    op.status = "active".into();
    save_session(dir, &state)?;
    Ok(state)
}

/// Mark operator as left.
pub fn leave_session(dir: &Path, scope: &Scope) -> Result<SessionState> {
    let mut state = load_session(dir)?;
    assert_ticket(scope, &state)?;
    let now = now_ms();
    let name = scope.operator.trim();
    let Some(op) = state
        .operators
        .iter_mut()
        .find(|o| o.name.eq_ignore_ascii_case(name))
    else {
        bail!("operator '{}' is not in this session", scope.operator);
    };
    op.status = "left".into();
    op.last_seen_unix_ms = now;
    save_session(dir, &state)?;
    Ok(state)
}

/// Append an operator note to notes.jsonl.
pub fn add_note(dir: &Path, scope: &Scope, text: &str) -> Result<()> {
    let state = load_session(dir)?;
    assert_ticket(scope, &state)?;
    let text = text.trim();
    if text.is_empty() {
        bail!("note text must not be empty");
    }
    // Must be an active (or known) operator.
    if !state
        .operators
        .iter()
        .any(|o| o.name.eq_ignore_ascii_case(scope.operator.trim()))
    {
        bail!("join the session before posting notes");
    }
    let note = SessionNote {
        ts_unix_ms: now_ms(),
        operator: scope.operator.clone(),
        ticket_id: scope.ticket_id.clone(),
        text: text.into(),
    };
    append_jsonl(&dir.join(NOTES_FILE), &note)
}

/// Append a detection alert into the shared session feed.
pub fn append_alert(dir: &Path, scope: &Scope, module: &str, alert: &Alert) -> Result<()> {
    let state = load_session(dir)?;
    assert_ticket(scope, &state)?;
    let ev = SessionAlertEvent {
        ts_unix_ms: now_ms(),
        operator: scope.operator.clone(),
        module: module.into(),
        alert: alert.clone(),
    };
    append_jsonl(&dir.join(ALERTS_FILE), &ev)
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

/// Human-readable status summary.
pub fn status_text(dir: &Path) -> Result<String> {
    let state = load_session(dir)?;
    let now = now_ms();
    let mut out = String::new();
    out.push_str(&format!(
        "session {}  ticket={}  title={}\n",
        state.session_id,
        state.ticket_id,
        if state.title.is_empty() {
            "-"
        } else {
            &state.title
        }
    ));
    out.push_str(&format!(
        "created_by={}  org={}  max_operators={}\n",
        state.created_by,
        if state.organization.is_empty() {
            "-"
        } else {
            &state.organization
        },
        state.max_operators
    ));
    if !state.allowed_operators.is_empty() {
        out.push_str(&format!(
            "allowlist: {}\n",
            state.allowed_operators.join(", ")
        ));
    }
    out.push_str("operators:\n");
    for op in &state.operators {
        let age_secs = now.saturating_sub(op.last_seen_unix_ms) / 1000;
        let live = live_label(&op.status, age_secs);
        out.push_str(&format!(
            "  - {} [{role}] status={live} last_seen={age_secs}s ago\n",
            op.name,
            role = op.role,
            live = live,
            age_secs = age_secs
        ));
    }
    let notes = count_lines(&dir.join(NOTES_FILE));
    let alerts = count_lines(&dir.join(ALERTS_FILE));
    out.push_str(&format!("shared notes={notes}  shared alerts={alerts}\n"));
    Ok(out)
}

fn count_lines(path: &Path) -> u64 {
    fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count() as u64)
        .unwrap_or(0)
}

fn live_label(status: &str, age_secs: u64) -> String {
    if status == "left" {
        "left".into()
    } else if age_secs > STALE_SECS {
        "stale".into()
    } else {
        "active".into()
    }
}

/// Build a dashboard-friendly presence snapshot from a session directory.
pub fn presence_snapshot(dir: &Path) -> Result<SessionDashInfo> {
    let state = load_session(dir)?;
    let now = now_ms();
    let mut operators = Vec::with_capacity(state.operators.len());
    let mut active_operators = 0u64;
    for op in &state.operators {
        let age_secs = now.saturating_sub(op.last_seen_unix_ms) / 1000;
        let live = live_label(&op.status, age_secs);
        if live == "active" {
            active_operators += 1;
        }
        operators.push(SessionOpView {
            name: op.name.clone(),
            role: op.role.clone(),
            live,
            last_seen_secs_ago: age_secs,
        });
    }
    operators.sort_by(|a, b| {
        live_rank(&a.live)
            .cmp(&live_rank(&b.live))
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(SessionDashInfo {
        session_id: state.session_id,
        ticket_id: state.ticket_id,
        title: state.title,
        operators,
        active_operators,
        notes_count: count_lines(&dir.join(NOTES_FILE)),
        shared_alerts_count: count_lines(&dir.join(ALERTS_FILE)),
        recent_notes: read_recent_notes(&dir.join(NOTES_FILE), 5),
    })
}

fn live_rank(live: &str) -> u8 {
    match live {
        "active" => 0,
        "stale" => 1,
        _ => 2,
    }
}

fn read_recent_notes(path: &Path, limit: usize) -> Vec<SessionNoteView> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    for line in raw.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(n) = serde_json::from_str::<SessionNote>(line) {
            notes.push(SessionNoteView {
                operator: n.operator,
                text: n.text,
                ts_unix_ms: n.ts_unix_ms,
            });
            if notes.len() >= limit {
                break;
            }
        }
    }
    notes.reverse();
    notes
}

/// Attach helper for detect/watch: ensure joined + heartbeat.
pub fn attach(dir: &Path, scope: &Scope, role: &str) -> Result<SessionState> {
    // Prefer heartbeat if already present; otherwise join.
    match heartbeat(dir, scope) {
        Ok(state) => Ok(state),
        Err(_) => join_session(dir, scope, role),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn lab_scope(op: &str) -> Scope {
        Scope {
            ticket_id: "AUTH-LAB-0001".into(),
            operator: op.into(),
            organization: "lab".into(),
            authorized: true,
            targets: vec!["127.0.0.1".into()],
            exclude: vec![],
            ports: vec![80],
            max_pps: 10,
            connect_timeout_ms: 800,
            max_hosts: 8,
            valid_until_unix: None,
        }
    }

    #[test]
    fn create_join_note_alert() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sess");
        let alice = lab_scope("alice");
        let state = create_session(&path, &alice, "Lab night", 4, vec![]).unwrap();
        assert_eq!(state.ticket_id, "AUTH-LAB-0001");
        assert_eq!(state.operators.len(), 1);

        let bob = lab_scope("bob");
        let state = join_session(&path, &bob, "observer").unwrap();
        assert_eq!(state.operators.len(), 2);

        add_note(&path, &bob, "seeing odd DNS").unwrap();
        append_alert(
            &path,
            &alice,
            "detect/ids_lite",
            &Alert {
                ts_unix_ms: 1,
                rule: "rare_port".into(),
                severity: "medium".into(),
                src: "10.0.0.1".into(),
                detail: "4444".into(),
            },
        )
        .unwrap();

        let text = status_text(&path).unwrap();
        assert!(text.contains("alice"));
        assert!(text.contains("bob"));
        assert!(text.contains("shared notes=1"));
        assert!(text.contains("shared alerts=1"));
    }

    #[test]
    fn rejects_wrong_ticket() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sess");
        let alice = lab_scope("alice");
        create_session(&path, &alice, "", 4, vec![]).unwrap();
        let mut eve = lab_scope("eve");
        eve.ticket_id = "OTHER".into();
        assert!(join_session(&path, &eve, "operator").is_err());
    }

    #[test]
    fn allowlist_enforced() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sess");
        let alice = lab_scope("alice");
        create_session(&path, &alice, "", 4, vec!["alice".into(), "bob".into()]).unwrap();
        let carol = lab_scope("carol");
        assert!(join_session(&path, &carol, "operator").is_err());
    }

    #[test]
    fn presence_snapshot_lists_active_ops() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sess");
        let alice = lab_scope("alice");
        create_session(&path, &alice, "Dash lab", 4, vec![]).unwrap();
        let bob = lab_scope("bob");
        join_session(&path, &bob, "observer").unwrap();
        add_note(&path, &bob, "presence check").unwrap();

        let snap = presence_snapshot(&path).unwrap();
        assert_eq!(snap.ticket_id, "AUTH-LAB-0001");
        assert_eq!(snap.title, "Dash lab");
        assert_eq!(snap.operators.len(), 2);
        assert!(snap.active_operators >= 1);
        assert_eq!(snap.notes_count, 1);
        assert!(snap
            .recent_notes
            .iter()
            .any(|n| n.text.contains("presence check")));
        assert!(snap.operators.iter().any(|o| o.live == "active"));
    }
}
