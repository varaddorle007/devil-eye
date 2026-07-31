//! CLI: time-window slice of an offline PCAP / PCAPNG file.

use std::io::{self, Write};

use anyhow::Result;

use crate::audit::AuditLog;
use crate::cli::SliceArgs;
use crate::slice::{slice_capture, TimeWindow};

/// Run capture time slice.
pub fn run(args: &SliceArgs) -> Result<()> {
    let window = TimeWindow {
        after: args.after,
        before: args.before,
    };

    let (operator, ticket) = if let Some(path) = &args.scope {
        let scope = crate::scope::Scope::load(path)?;
        (scope.operator, scope.ticket_id)
    } else {
        ("anonymous".into(), "slice-no-scope".into())
    };

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "slice/captures",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "read": args.read.display().to_string(),
            "write": args.write.display().to_string(),
            "after": args.after,
            "before": args.before,
        }),
        "ok",
    )?;

    let stats = slice_capture(&args.read, &args.write, window)?;

    writeln!(
        io::stderr(),
        "slice complete: read={} written={} -> {} (audited -> {})",
        stats.read,
        stats.written,
        args.write.display(),
        audit.path().display()
    )?;

    audit.info(
        "slice/captures",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "read": stats.read,
            "written": stats.written,
            "output_pcapng": stats.output_pcapng,
            "write": args.write.display().to_string(),
        }),
        "ok",
    )?;

    Ok(())
}
