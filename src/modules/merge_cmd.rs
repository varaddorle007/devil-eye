//! CLI: chronologically merge offline PCAP / PCAPNG files.

use std::io::{self, Write};

use anyhow::{bail, Result};

use crate::audit::AuditLog;
use crate::cli::MergeArgs;
use crate::merge::merge_captures;

/// Run capture merge.
pub fn run(args: &MergeArgs) -> Result<()> {
    if args.inputs.len() < 2 {
        bail!("merge requires at least two input files");
    }

    let (operator, ticket) = if let Some(path) = &args.scope {
        let scope = crate::scope::Scope::load(path)?;
        (scope.operator, scope.ticket_id)
    } else {
        ("anonymous".into(), "merge-no-scope".into())
    };

    let audit = AuditLog::open(&args.audit_log);
    audit.info(
        "merge/captures",
        "start",
        &operator,
        &ticket,
        serde_json::json!({
            "inputs": args.inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "write": args.write.display().to_string(),
        }),
        "ok",
    )?;

    let stats = merge_captures(&args.inputs, &args.write)?;

    writeln!(
        io::stderr(),
        "merge complete: files={} packets={} -> {} (audited -> {})",
        stats.input_files,
        stats.packets,
        args.write.display(),
        audit.path().display()
    )?;

    audit.info(
        "merge/captures",
        "finish",
        &operator,
        &ticket,
        serde_json::json!({
            "input_files": stats.input_files,
            "packets": stats.packets,
            "output_pcapng": stats.output_pcapng,
            "write": args.write.display().to_string(),
        }),
        "ok",
    )?;

    Ok(())
}
