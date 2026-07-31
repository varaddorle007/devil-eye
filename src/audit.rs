//! Append-only JSONL audit log for governance / evidence.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

/// One audit event written as a single JSON line.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub ts_unix_ms: u64,
    pub action: String,
    pub module: String,
    pub operator: String,
    pub ticket_id: String,
    pub detail: serde_json::Value,
    pub result: String,
}

/// Append-only audit logger.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit log {}", self.path.display()))?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    pub fn info(
        &self,
        module: &str,
        action: &str,
        operator: &str,
        ticket_id: &str,
        detail: serde_json::Value,
        result: &str,
    ) -> Result<()> {
        self.record(&AuditEvent {
            ts_unix_ms: now_ms(),
            action: action.into(),
            module: module.into(),
            operator: operator.into(),
            ticket_id: ticket_id.into(),
            detail,
            result: result.into(),
        })
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn appends_json_line() {
        let f = NamedTempFile::new().unwrap();
        let log = AuditLog::open(f.path());
        log.info(
            "test",
            "unit",
            "op",
            "T1",
            serde_json::json!({"ok": true}),
            "ok",
        )
        .unwrap();
        let text = std::fs::read_to_string(f.path()).unwrap();
        assert!(text.contains("\"ticket_id\":\"T1\""));
        assert!(text.ends_with('\n'));
    }
}
