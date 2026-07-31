//! Time-window slice of an offline PCAP / PCAPNG capture.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::capture::{is_pcapng_path, CaptureWriter, OfflineSource};

/// Inclusive/exclusive window in Unix seconds (packet `timestamp_secs`).
#[derive(Debug, Clone, Copy)]
pub struct TimeWindow {
    /// Keep packets with `timestamp_secs >= after` (if set).
    pub after: Option<u32>,
    /// Keep packets with `timestamp_secs < before` (if set).
    pub before: Option<u32>,
}

impl TimeWindow {
    pub fn validate(self) -> Result<()> {
        if self.after.is_none() && self.before.is_none() {
            bail!("slice requires --after and/or --before");
        }
        if let (Some(a), Some(b)) = (self.after, self.before) {
            if a >= b {
                bail!("--after ({a}) must be less than --before ({b})");
            }
        }
        Ok(())
    }

    fn contains(self, secs: u32) -> bool {
        if let Some(a) = self.after {
            if secs < a {
                return false;
            }
        }
        if let Some(b) = self.before {
            if secs >= b {
                return false;
            }
        }
        true
    }
}

/// Summary of a slice run.
#[derive(Debug, Clone)]
pub struct SliceStats {
    pub read: u64,
    pub written: u64,
    pub output_pcapng: bool,
}

/// Copy packets from `input` whose timestamps fall in `window` into `output`.
pub fn slice_capture(input: &Path, output: &Path, window: TimeWindow) -> Result<SliceStats> {
    window.validate()?;

    let mut src =
        OfflineSource::open(input).with_context(|| format!("failed to open {}", input.display()))?;
    let mut writer = CaptureWriter::create(output, src.snaplen.max(1))
        .with_context(|| format!("failed to create {}", output.display()))?;

    let mut read = 0u64;
    let mut written = 0u64;
    while let Some(pkt) = src.next_packet()? {
        read = read.saturating_add(1);
        if window.contains(pkt.timestamp_secs) {
            writer.write_packet(&pkt)?;
            written = written.saturating_add(1);
        }
    }
    writer.flush()?;

    Ok(SliceStats {
        read,
        written,
        output_pcapng: is_pcapng_path(output),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureWriter, RawPacket};
    use std::path::PathBuf;

    fn write_three(path: &Path) {
        let mut w = CaptureWriter::create(path, 65535).unwrap();
        for (secs, tag) in [(100u32, 0x11u8), (200, 0x22), (300, 0x33)] {
            w.write_packet(&RawPacket {
                timestamp_secs: secs,
                timestamp_usecs: 0,
                orig_len: 4,
                data: vec![tag, tag, tag, tag],
            })
            .unwrap();
        }
        w.flush().unwrap();
    }

    #[test]
    fn slices_after_before() {
        let dir = tempfile::tempdir().unwrap();
        let inp = dir.path().join("in.pcap");
        let out = dir.path().join("out.pcap");
        write_three(&inp);

        let stats = slice_capture(
            &inp,
            &out,
            TimeWindow {
                after: Some(150),
                before: Some(250),
            },
        )
        .unwrap();
        assert_eq!(stats.read, 3);
        assert_eq!(stats.written, 1);

        let mut src = OfflineSource::open(&out).unwrap();
        let pkt = src.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_secs, 200);
        assert_eq!(pkt.data[0], 0x22);
        assert!(src.next_packet().unwrap().is_none());
    }

    #[test]
    fn slices_after_only() {
        let dir = tempfile::tempdir().unwrap();
        let inp = dir.path().join("in.pcap");
        let out = dir.path().join("out.pcapng");
        write_three(&inp);
        let stats = slice_capture(
            &inp,
            &out,
            TimeWindow {
                after: Some(200),
                before: None,
            },
        )
        .unwrap();
        assert_eq!(stats.written, 2);
        assert!(stats.output_pcapng);
    }

    #[test]
    fn rejects_empty_window() {
        let err = TimeWindow {
            after: None,
            before: None,
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("--after"));
    }

    #[test]
    fn slices_fixture_dns() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dns-slice.pcap");
        // Fixture uses ~1_700_000_000; window that includes it.
        let stats = slice_capture(
            &root.join("dns_query.pcap"),
            &out,
            TimeWindow {
                after: Some(1_699_999_000),
                before: Some(1_700_001_000),
            },
        )
        .unwrap();
        assert_eq!(stats.written, 1);
    }
}
