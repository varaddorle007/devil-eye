//! Chronological merge of offline PCAP / PCAPNG captures.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::capture::{is_pcapng_path, CaptureWriter, OfflineSource, RawPacket};

/// Summary of a merge run.
#[derive(Debug, Clone)]
pub struct MergeStats {
    pub input_files: usize,
    pub packets: u64,
    pub output_pcapng: bool,
}

/// Read all packets from `inputs`, sort by timestamp, write to `output`.
///
/// Equal timestamps keep a stable order (first input file wins ties).
pub fn merge_captures(inputs: &[impl AsRef<Path>], output: &Path) -> Result<MergeStats> {
    if inputs.len() < 2 {
        bail!("merge requires at least two input capture files");
    }

    let mut packets: Vec<(u32, RawPacket)> = Vec::new();
    for (idx, path) in inputs.iter().enumerate() {
        let path = path.as_ref();
        let mut src = OfflineSource::open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let file_ord = u32::try_from(idx).unwrap_or(u32::MAX);
        while let Some(pkt) = src.next_packet()? {
            packets.push((file_ord, pkt));
        }
    }

    packets.sort_by(|a, b| {
        a.1.timestamp_secs
            .cmp(&b.1.timestamp_secs)
            .then(a.1.timestamp_usecs.cmp(&b.1.timestamp_usecs))
            .then(a.0.cmp(&b.0))
    });

    let mut writer = CaptureWriter::create(output, 65535)
        .with_context(|| format!("failed to create {}", output.display()))?;
    for (_, pkt) in &packets {
        writer.write_packet(pkt)?;
    }
    writer.flush()?;

    Ok(MergeStats {
        input_files: inputs.len(),
        packets: packets.len() as u64,
        output_pcapng: is_pcapng_path(output),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::RawPacket;
    use std::path::PathBuf;

    #[test]
    fn merges_two_fixtures_chronologically() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("merged.pcap");

        // dns_query and http_get fixtures use different timestamps in ensure_fixtures
        // (1_700_000_000 vs similar). Use capture write path: merge classic fixtures.
        let a = root.join("dns_query.pcap");
        let b = root.join("http_get.pcap");
        let stats = merge_captures(&[a.as_path(), b.as_path()], &out).unwrap();
        assert_eq!(stats.input_files, 2);
        assert_eq!(stats.packets, 2);
        assert!(!stats.output_pcapng);

        let mut src = OfflineSource::open(&out).unwrap();
        let first = src.next_packet().unwrap().unwrap();
        let second = src.next_packet().unwrap().unwrap();
        assert!(src.next_packet().unwrap().is_none());
        let t1 = (
            first.timestamp_secs,
            first.timestamp_usecs,
        );
        let t2 = (
            second.timestamp_secs,
            second.timestamp_usecs,
        );
        assert!(t1 <= t2);
    }

    #[test]
    fn writes_pcapng_when_extension_matches() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("merged.pcapng");
        let stats = merge_captures(
            &[root.join("dns_query.pcap"), root.join("arp_request.pcap")],
            &out,
        )
        .unwrap();
        assert!(stats.output_pcapng);
        let mut src = OfflineSource::open(&out).unwrap();
        assert!(src.next_packet().unwrap().is_some());
        assert!(src.next_packet().unwrap().is_some());
        assert!(src.next_packet().unwrap().is_none());
    }

    #[test]
    fn rejects_single_input() {
        let err = merge_captures(
            &["a.pcap"],
            Path::new("out.pcap"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least two"));
    }

    #[test]
    fn sorts_equal_ts_by_input_order() {
        // Build two tiny pcaps with identical timestamps via CaptureWriter.
        use crate::capture::CaptureWriter;
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.pcap");
        let b = dir.path().join("b.pcap");
        let out = dir.path().join("out.pcap");

        let pkt_a = RawPacket {
            timestamp_secs: 100,
            timestamp_usecs: 0,
            orig_len: 4,
            data: vec![0xaa, 0xaa, 0xaa, 0xaa],
        };
        let pkt_b = RawPacket {
            timestamp_secs: 100,
            timestamp_usecs: 0,
            orig_len: 4,
            data: vec![0xbb, 0xbb, 0xbb, 0xbb],
        };
        {
            let mut w = CaptureWriter::create(&a, 65535).unwrap();
            w.write_packet(&pkt_a).unwrap();
            w.flush().unwrap();
        }
        {
            let mut w = CaptureWriter::create(&b, 65535).unwrap();
            w.write_packet(&pkt_b).unwrap();
            w.flush().unwrap();
        }

        merge_captures(&[a.as_path(), b.as_path()], &out).unwrap();
        let mut src = OfflineSource::open(&out).unwrap();
        let first = src.next_packet().unwrap().unwrap();
        let second = src.next_packet().unwrap().unwrap();
        assert_eq!(first.data, pkt_a.data);
        assert_eq!(second.data, pkt_b.data);
    }
}
