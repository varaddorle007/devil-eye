//! CLI for multi-operator engagement sessions.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::audit::AuditLog;
use crate::cli::{
    SessionArgs, SessionCommand, SessionCreateArgs, SessionDirArgs, SessionJoinArgs,
    SessionNoteArgs, SessionScopeDirArgs,
};
use crate::scope::Scope;
use crate::session::{
    add_note, create_session, heartbeat, join_session, leave_session, load_session, status_text,
};

/// Dispatch session subcommands.
pub fn run(args: &SessionArgs) -> Result<()> {
    match &args.command {
        SessionCommand::Create(a) => run_create(a),
        SessionCommand::Join(a) => run_join(a),
        SessionCommand::Heartbeat(a) => run_heartbeat(a),
        SessionCommand::Leave(a) => run_leave(a),
        SessionCommand::Status(a) => run_status(a),
        SessionCommand::Note(a) => run_note(a),
    }
}

fn run_create(args: &SessionCreateArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let allow = args
        .allow
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let state = create_session(
        &args.session_dir,
        &scope,
        &args.title,
        args.max_operators,
        allow,
    )?;
    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "session",
        "create",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "session_dir": args.session_dir.display().to_string(),
            "session_id": state.session_id,
            "max_operators": state.max_operators,
        }),
        "ok",
    )?;
    writeln!(
        io::stdout(),
        "created session {} at {}\nticket={} lead={}",
        state.session_id,
        args.session_dir.display(),
        state.ticket_id,
        state.created_by
    )?;
    Ok(())
}

fn run_join(args: &SessionJoinArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let state = join_session(&args.session_dir, &scope, &args.role)?;
    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "session",
        "join",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "session_dir": args.session_dir.display().to_string(),
            "session_id": state.session_id,
            "role": args.role,
        }),
        "ok",
    )?;
    writeln!(
        io::stdout(),
        "joined {} as {} (operators={})",
        state.session_id,
        scope.operator,
        state.operators.len()
    )?;
    print!("{}", status_text(&args.session_dir)?);
    Ok(())
}

fn run_heartbeat(args: &SessionScopeDirArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let state = heartbeat(&args.session_dir, &scope)?;
    writeln!(
        io::stdout(),
        "heartbeat ok session={} operator={}",
        state.session_id,
        scope.operator
    )?;
    Ok(())
}

fn run_leave(args: &SessionScopeDirArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    let state = leave_session(&args.session_dir, &scope)?;
    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "session",
        "leave",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "session_dir": args.session_dir.display().to_string(),
            "session_id": state.session_id,
        }),
        "ok",
    )?;
    writeln!(io::stdout(), "left session {}", state.session_id)?;
    Ok(())
}

fn run_status(args: &SessionDirArgs) -> Result<()> {
    let _ = load_session(&args.session_dir)
        .with_context(|| format!("no session at {}", args.session_dir.display()))?;
    print!("{}", status_text(&args.session_dir)?);
    Ok(())
}

fn run_note(args: &SessionNoteArgs) -> Result<()> {
    let scope = Scope::load(&args.scope)?;
    add_note(&args.session_dir, &scope, &args.text)?;
    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "session",
        "note",
        &scope.operator,
        &scope.ticket_id,
        serde_json::json!({
            "session_dir": args.session_dir.display().to_string(),
            "chars": args.text.len(),
        }),
        "ok",
    )?;
    writeln!(io::stdout(), "note recorded")?;
    Ok(())
}

/// Shared helper: require scope when attaching a session from detect/watch.
pub fn require_scope_for_session(
    session_dir: &Option<PathBuf>,
    scope: &Option<PathBuf>,
) -> Result<()> {
    if session_dir.is_some() && scope.is_none() {
        bail!("--session-dir requires --scope (ticket-authenticated multi-operator session)");
    }
    Ok(())
}
