//! CLI: compare two detect-compatible alert JSON reports.

use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::audit::AuditLog;
use crate::cli::DiffArgs;
use crate::diff::{diff_alerts, format_diff_text, load_alerts, AlertDiff, DiffKeyMode};

#[derive(Debug, Serialize)]
struct DiffReport {
    module: String,
    before: String,
    after: String,
    diff: AlertDiff,
}

/// Run alert report comparison.
pub fn run(args: &DiffArgs) -> Result<()> {
    let mode = DiffKeyMode::parse(&args.key)?;
    let before = load_alerts(&args.before)?;
    let after = load_alerts(&args.after)?;

    let (operator, ticket) = if let Some(path) = &args.scope {
        let scope = crate::scope::Scope::load(path)?;
        (scope.operator, scope.ticket_id)
    } else {
        ("anonymous".into(), "diff-no-scope".into())
    };

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "diff/alerts",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "before": args.before.display().to_string(),
            "after": args.after.display().to_string(),
            "key": mode.as_str(),
            "json_out": args.json_out.as_ref().map(|p| p.display().to_string()),
        }),
        "ok",
    )?;

    let diff = diff_alerts(&before, &after, mode);
    let text = format_diff_text(&diff, true);
    write!(io::stdout(), "{text}")?;

    if let Some(path) = &args.json_out {
        let report = DiffReport {
            module: "diff/alerts".into(),
            before: args.before.display().to_string(),
            after: args.after.display().to_string(),
            diff: diff.clone(),
        };
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("wrote diff JSON {}", path.display());
    }

    let gone: u64 = diff.only_before.iter().map(|b| b.count).sum();
    let new: u64 = diff.only_after.iter().map(|b| b.count).sum();
    writeln!(
        io::stderr(),
        "diff complete: gone={gone} new={new} unchanged={} (audited -> {})",
        diff.unchanged,
        audit.path().display()
    )?;

    audit.info(
        "diff/alerts",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "before_total": diff.before_total,
            "after_total": diff.after_total,
            "unchanged": diff.unchanged,
            "gone": gone,
            "new": new,
        }),
        "ok",
    )?;

    if args.fail_on_diff && (gone > 0 || new > 0) {
        bail!("alert sets differ (gone={gone} new={new})");
    }

    Ok(())
}
