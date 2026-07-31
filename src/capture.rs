//! Packet capture sources: offline classical PCAP / PCAPNG and optional live Npcap/libpcap.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::bpf_lite::PacketFilter;
use crate::cli::Args;

const PCAP_MAGIC_USEC: u32 = 0xa1_b2_c3_d4;
const PCAP_MAGIC_USEC_SWAPPED: u32 = 0xd4_c3_b2_a1;
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const LINKTYPE_ETHERNET: u32 = 1;

const BLOCK_SHB: u32 = 0x0a0d_0d0a;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_SPB: u32 = 0x0000_0003;
const BLOCK_EPB: u32 = 0x0000_0006;

/// Raw captured frame with timestamp and lengths.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub timestamp_secs: u32,
    pub timestamp_usecs: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// Capture-driver drop counters when available.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    /// Packets received by the driver.
    pub received: u64,
    /// Packets dropped by the capture mechanism.
    pub dropped: u64,
    /// Packets dropped by the interface.
    pub if_dropped: u64,
}

/// Network interface metadata.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
}

/// Sink that appends packets to a classical PCAP file.
pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    pub fn create(path: &Path, snaplen: u32) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("failed to create PCAP file {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        write_global_header(&mut writer, snaplen)?;
        Ok(Self { writer })
    }

    pub fn write_packet(&mut self, packet: &RawPacket) -> Result<()> {
        let incl = u32::try_from(packet.data.len()).unwrap_or(u32::MAX);
        self.writer
            .write_all(&packet.timestamp_secs.to_le_bytes())?;
        self.writer
            .write_all(&packet.timestamp_usecs.to_le_bytes())?;
        self.writer.write_all(&incl.to_le_bytes())?;
        self.writer.write_all(&packet.orig_len.to_le_bytes())?;
        self.writer.write_all(&packet.data)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Unified packet source (live or offline).
pub enum PacketSource {
    Offline(OfflineSource),
    /// Offline PCAP/PCAPNG with software filter (`-f`, no libpcap required).
    OfflineSoft(OfflineSoftSource),
    #[cfg(feature = "live")]
    Live(LiveSource),
}

impl PacketSource {
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        match self {
            Self::Offline(src) => src.next_packet(),
            Self::OfflineSoft(src) => src.next_packet(),
            #[cfg(feature = "live")]
            Self::Live(src) => src.next_packet(),
        }
    }

    pub fn open_writer(&self, path: &Path) -> Result<PcapWriter> {
        let snaplen = match self {
            Self::Offline(src) => src.snaplen,
            Self::OfflineSoft(src) => src.inner.snaplen,
            #[cfg(feature = "live")]
            Self::Live(src) => src.snaplen,
        };
        PcapWriter::create(path, snaplen)
    }

    pub fn capture_stats(&mut self) -> Result<CaptureStats> {
        match self {
            Self::Offline(_) | Self::OfflineSoft(_) => Ok(CaptureStats::default()),
            #[cfg(feature = "live")]
            Self::Live(src) => src.capture_stats(),
        }
    }
}

/// Offline reader that skips frames not matching a software filter.
pub struct OfflineSoftSource {
    inner: OfflineSource,
    filter: PacketFilter,
}

impl OfflineSoftSource {
    fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        loop {
            let Some(pkt) = self.inner.next_packet()? else {
                return Ok(None);
            };
            if self.filter.matches(&pkt.data) {
                return Ok(Some(pkt));
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PcapNgIface {
    linktype: u16,
    snaplen: u32,
    /// Timestamp units per second (default 1_000_000 = microseconds).
    ts_units_per_sec: u64,
}

enum OfflineFormat {
    Classic {
        swapped: bool,
    },
    PcapNg {
        little_endian: bool,
        interfaces: Vec<PcapNgIface>,
    },
}

/// Offline PCAP / PCAPNG file reader (pure Rust — no Npcap required).
pub struct OfflineSource {
    reader: BufReader<File>,
    format: OfflineFormat,
    pub snaplen: u32,
    eof: bool,
}

impl OfflineSource {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open capture file {}", path.display()))?;
        let mut reader = BufReader::new(file);
        let mut magic_bytes = [0u8; 4];
        reader
            .read_exact(&mut magic_bytes)
            .context("failed reading capture file magic")?;
        let magic_le = u32::from_le_bytes(magic_bytes);

        if magic_le == PCAPNG_SHB {
            let (little_endian, snaplen, interfaces) =
                read_pcapng_preamble(&mut reader, magic_bytes)?;
            return Ok(Self {
                reader,
                format: OfflineFormat::PcapNg {
                    little_endian,
                    interfaces,
                },
                snaplen,
                eof: false,
            });
        }

        let (swapped, snaplen) = read_global_header_after_magic(&mut reader, magic_bytes)?;
        Ok(Self {
            reader,
            format: OfflineFormat::Classic { swapped },
            snaplen,
            eof: false,
        })
    }

    /// Read the next packet, or `None` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        if self.eof {
            return Ok(None);
        }
        match &mut self.format {
            OfflineFormat::Classic { swapped } => {
                Self::next_classic(&mut self.reader, *swapped, self.snaplen, &mut self.eof)
            }
            OfflineFormat::PcapNg {
                little_endian,
                interfaces,
            } => Self::next_pcapng(
                &mut self.reader,
                *little_endian,
                interfaces,
                &mut self.snaplen,
                &mut self.eof,
            ),
        }
    }

    fn next_classic(
        reader: &mut BufReader<File>,
        swapped: bool,
        snaplen: u32,
        eof: &mut bool,
    ) -> Result<Option<RawPacket>> {
        let mut hdr = [0u8; 16];
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                *eof = true;
                return Ok(None);
            }
            Err(err) => return Err(err).context("failed reading PCAP packet header"),
        }

        let ts_sec = read_u32(&hdr[0..4], swapped);
        let ts_usec = read_u32(&hdr[4..8], swapped);
        let incl_len = read_u32(&hdr[8..12], swapped);
        let orig_len = read_u32(&hdr[12..16], swapped);

        if incl_len > snaplen.saturating_mul(2).max(1_048_576) {
            bail!("implausible packet length {incl_len} in PCAP");
        }

        let mut data = vec![0u8; incl_len as usize];
        reader
            .read_exact(&mut data)
            .context("failed reading PCAP packet data")?;

        Ok(Some(RawPacket {
            timestamp_secs: ts_sec,
            timestamp_usecs: ts_usec,
            orig_len,
            data,
        }))
    }

    fn next_pcapng(
        reader: &mut BufReader<File>,
        little_endian: bool,
        interfaces: &mut Vec<PcapNgIface>,
        snaplen: &mut u32,
        eof: &mut bool,
    ) -> Result<Option<RawPacket>> {
        loop {
            let Some((btype, body)) = read_pcapng_block(reader, little_endian)? else {
                *eof = true;
                return Ok(None);
            };
            match btype {
                BLOCK_SHB => {
                    // Additional section — keep current endianness; ignore nested BOM mismatches.
                }
                BLOCK_IDB => {
                    let iface = parse_idb(&body, little_endian)?;
                    if iface.linktype as u32 != LINKTYPE_ETHERNET {
                        eprintln!(
                            "devil-eye: warning: PCAPNG linktype {} is not Ethernet (1); decode may fail",
                            iface.linktype
                        );
                    }
                    *snaplen = (*snaplen).max(iface.snaplen.max(1));
                    interfaces.push(iface);
                }
                BLOCK_EPB => {
                    if let Some(pkt) = parse_epb(&body, little_endian, interfaces)? {
                        return Ok(Some(pkt));
                    }
                }
                BLOCK_SPB => {
                    if let Some(pkt) = parse_spb(&body, little_endian, interfaces)? {
                        return Ok(Some(pkt));
                    }
                }
                _ => {
                    // Skip unknown / optional blocks (NRB, ISB, custom, …).
                }
            }
        }
    }
}

#[cfg(feature = "live")]
pub struct LiveSource {
    capture: pcap::Capture<pcap::Active>,
    pub snaplen: u32,
}

#[cfg(feature = "live")]
impl LiveSource {
    fn open_iface(args: &Args) -> Result<Self> {
        let name = args
            .interface
            .as_deref()
            .context("live capture requires -i/--interface")?;

        let inactive = pcap::Capture::from_device(name)
            .with_context(|| format!("failed to open interface '{name}'"))?
            .promisc(args.promisc)
            .snaplen(args.snaplen)
            .timeout(args.timeout_ms);

        let mut capture = inactive
            .open()
            .with_context(|| format!("failed to activate capture on '{name}'"))?;

        if let Some(filter) = &args.filter {
            capture
                .filter(filter, true)
                .with_context(|| format!("invalid BPF filter '{filter}'"))?;
        }

        Ok(Self {
            capture,
            snaplen: u32::try_from(args.snaplen).unwrap_or(65535),
        })
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        match self.capture.next_packet() {
            Ok(pkt) => Ok(Some(packet_from_pcap(&pkt))),
            Err(pcap::Error::TimeoutExpired) => bail!("timeout"),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(err) => Err(err).context("live capture read failed"),
        }
    }

    fn capture_stats(&mut self) -> Result<CaptureStats> {
        let s = self.capture.stats().context("pcap_stats failed")?;
        Ok(CaptureStats {
            received: u64::from(s.received),
            dropped: u64::from(s.dropped),
            if_dropped: u64::from(s.if_dropped),
        })
    }
}

#[cfg(feature = "live")]
fn packet_from_pcap(pkt: &pcap::Packet<'_>) -> RawPacket {
    let header = pkt.header;
    RawPacket {
        timestamp_secs: header.ts.tv_sec as u32,
        timestamp_usecs: header.ts.tv_usec as u32,
        orig_len: header.len,
        data: pkt.data.to_vec(),
    }
}

/// List capture interfaces.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    #[cfg(feature = "live")]
    {
        let devices = pcap::Device::list().context("failed to list capture devices")?;
        Ok(devices
            .into_iter()
            .map(|d| InterfaceInfo {
                name: d.name,
                description: d.desc,
                addresses: d
                    .addresses
                    .into_iter()
                    .map(|a| format!("{:?}", a.addr))
                    .collect(),
            })
            .collect())
    }
    #[cfg(not(feature = "live"))]
    {
        bail!(live_feature_help("listing interfaces"));
    }
}

/// Open a live or offline packet source from CLI args.
pub fn open_source(args: &Args) -> Result<PacketSource> {
    if let Some(path) = &args.read {
        let src = OfflineSource::open(path)?;
        if let Some(expr) = &args.filter {
            let filter = PacketFilter::parse(expr)
                .with_context(|| format!("invalid offline filter '{expr}'"))?;
            return Ok(PacketSource::OfflineSoft(OfflineSoftSource {
                inner: src,
                filter,
            }));
        }
        return Ok(PacketSource::Offline(src));
    }

    #[cfg(feature = "live")]
    {
        let src = LiveSource::open_iface(args)?;
        Ok(PacketSource::Live(src))
    }

    #[cfg(not(feature = "live"))]
    {
        let _ = args;
        bail!(live_feature_help("live capture"));
    }
}

#[cfg(not(feature = "live"))]
fn live_feature_help(action: &str) -> String {
    format!(
        "{action} requires building with `--features live` and installing \
Npcap (Windows) or libpcap (Unix).\n\
  Windows: https://npcap.com/ — install Npcap + SDK, set LIB to the SDK Lib folder,\n\
  then: cargo build --release --features live\n\
Without live support you can still use -r/--read to replay PCAP/PCAPNG files \
(and -f with the built-in offline filter subset)."
    )
}

fn write_global_header(w: &mut impl Write, snaplen: u32) -> Result<()> {
    w.write_all(&PCAP_MAGIC_USEC.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?; // major
    w.write_all(&4u16.to_le_bytes())?; // minor
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&snaplen.to_le_bytes())?;
    w.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
    Ok(())
}

fn read_global_header_after_magic(r: &mut impl Read, magic_bytes: [u8; 4]) -> Result<(bool, u32)> {
    let mut rest = [0u8; 20];
    r.read_exact(&mut rest)
        .context("failed reading PCAP global header")?;
    let mut hdr = [0u8; 24];
    hdr[..4].copy_from_slice(&magic_bytes);
    hdr[4..].copy_from_slice(&rest);
    let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let swapped = match magic {
        PCAP_MAGIC_USEC => false,
        PCAP_MAGIC_USEC_SWAPPED => true,
        other => bail!("unsupported capture magic 0x{other:08x} (expect classical PCAP or PCAPNG)"),
    };
    let snaplen = read_u32(&hdr[16..20], swapped);
    let network = read_u32(&hdr[20..24], swapped);
    if network != LINKTYPE_ETHERNET {
        eprintln!("devil-eye: warning: linktype {network} is not Ethernet (1); decode may fail");
    }
    Ok((swapped, snaplen.max(1)))
}

/// Consume the already-read SHB type bytes and finish opening a PCAPNG section.
fn read_pcapng_preamble(
    r: &mut impl Read,
    _type_bytes: [u8; 4],
) -> Result<(bool, u32, Vec<PcapNgIface>)> {
    // length (4) + byte-order magic (4) — BOM tells us how to read length.
    let mut len_and_bom = [0u8; 8];
    r.read_exact(&mut len_and_bom)
        .context("failed reading PCAPNG SHB length/BOM")?;

    let bom_le = u32::from_le_bytes(len_and_bom[4..8].try_into().unwrap());
    let little_endian = match bom_le {
        0x1a2b_3c4d => true,  // BOM stored little-endian
        0x4d3c_2b1a => false, // BOM stored big-endian
        other => bail!("unsupported PCAPNG byte-order magic 0x{other:08x}"),
    };
    let total_len = if little_endian {
        u32::from_le_bytes(len_and_bom[0..4].try_into().unwrap())
    } else {
        u32::from_be_bytes(len_and_bom[0..4].try_into().unwrap())
    };
    if total_len < 28 || !total_len.is_multiple_of(4) {
        bail!("invalid PCAPNG SHB total length {total_len}");
    }

    // Already consumed: type(4) + length(4) + BOM(4) = 12. Remaining includes trailing length.
    let rest_len = (total_len as usize).saturating_sub(12);
    let mut rest = vec![0u8; rest_len];
    r.read_exact(&mut rest)
        .context("failed reading PCAPNG SHB remainder")?;
    if rest.len() < 4 {
        bail!("truncated PCAPNG SHB");
    }
    let trailing = read_u32_endian(&rest[rest.len() - 4..], little_endian);
    if trailing != total_len {
        bail!("PCAPNG SHB trailing length mismatch");
    }
    Ok((little_endian, 65535, Vec::new()))
}

fn read_pcapng_block(r: &mut impl Read, little_endian: bool) -> Result<Option<(u32, Vec<u8>)>> {
    let mut hdr = [0u8; 8];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("failed reading PCAPNG block header"),
    }
    let btype = read_u32_endian(&hdr[0..4], little_endian);
    let total = read_u32_endian(&hdr[4..8], little_endian);
    if total < 12 || !total.is_multiple_of(4) {
        bail!("invalid PCAPNG block length {total} (type=0x{btype:08x})");
    }
    if total > 64 * 1024 * 1024 {
        bail!("PCAPNG block too large ({total} bytes)");
    }
    let rest_len = (total as usize).saturating_sub(8);
    let mut rest = vec![0u8; rest_len];
    r.read_exact(&mut rest)
        .context("failed reading PCAPNG block body")?;
    if rest.len() < 4 {
        bail!("truncated PCAPNG block");
    }
    let trailing = read_u32_endian(&rest[rest.len() - 4..], little_endian);
    if trailing != total {
        bail!("PCAPNG block trailing length mismatch");
    }
    let body = rest[..rest.len() - 4].to_vec();
    Ok(Some((btype, body)))
}

fn parse_idb(body: &[u8], little_endian: bool) -> Result<PcapNgIface> {
    if body.len() < 8 {
        bail!("PCAPNG IDB too short");
    }
    let linktype = read_u16_endian(&body[0..2], little_endian);
    let snaplen = read_u32_endian(&body[4..8], little_endian).max(1);
    let mut ts_units_per_sec = 1_000_000u64;
    if body.len() > 8 {
        ts_units_per_sec = parse_tsresol_option(&body[8..], little_endian).unwrap_or(1_000_000);
    }
    Ok(PcapNgIface {
        linktype,
        snaplen,
        ts_units_per_sec,
    })
}

fn parse_tsresol_option(options: &[u8], little_endian: bool) -> Option<u64> {
    let mut i = 0usize;
    while i + 4 <= options.len() {
        let code = read_u16_endian(&options[i..i + 2], little_endian);
        let len = read_u16_endian(&options[i + 2..i + 4], little_endian) as usize;
        i += 4;
        if i + len > options.len() {
            break;
        }
        if code == 9 && len >= 1 {
            // if_tsresol
            let v = options[i];
            let units = if v & 0x80 == 0 {
                10u64.saturating_pow(u32::from(v))
            } else {
                2u64.saturating_pow(u32::from(v & 0x7f))
            };
            return Some(units.max(1));
        }
        if code == 0 {
            break; // opt_endofopt
        }
        i += align4(len);
    }
    None
}

fn parse_epb(
    body: &[u8],
    little_endian: bool,
    interfaces: &[PcapNgIface],
) -> Result<Option<RawPacket>> {
    if body.len() < 20 {
        bail!("PCAPNG EPB too short");
    }
    let iface_id = read_u32_endian(&body[0..4], little_endian) as usize;
    let ts_high = read_u32_endian(&body[4..8], little_endian);
    let ts_low = read_u32_endian(&body[8..12], little_endian);
    let caplen = read_u32_endian(&body[12..16], little_endian);
    let origlen = read_u32_endian(&body[16..20], little_endian);
    if caplen as usize > body.len().saturating_sub(20) {
        bail!("PCAPNG EPB captured length exceeds block");
    }
    if caplen > 16 * 1024 * 1024 {
        bail!("implausible PCAPNG packet length {caplen}");
    }
    let data = body[20..20 + caplen as usize].to_vec();
    let iface = interfaces.get(iface_id);
    let units = iface
        .map(|i| i.ts_units_per_sec)
        .unwrap_or(1_000_000)
        .max(1);
    let ts = ((u64::from(ts_high) << 32) | u64::from(ts_low)) as u128;
    let (secs, usecs) = split_timestamp(ts, units);
    Ok(Some(RawPacket {
        timestamp_secs: secs,
        timestamp_usecs: usecs,
        orig_len: origlen,
        data,
    }))
}

fn parse_spb(
    body: &[u8],
    little_endian: bool,
    interfaces: &[PcapNgIface],
) -> Result<Option<RawPacket>> {
    if body.len() < 4 {
        bail!("PCAPNG SPB too short");
    }
    let origlen = read_u32_endian(&body[0..4], little_endian);
    let snap = interfaces.first().map(|i| i.snaplen).unwrap_or(65535);
    let caplen = origlen.min(snap);
    if caplen as usize > body.len().saturating_sub(4) {
        bail!("PCAPNG SPB captured length exceeds block");
    }
    let data = body[4..4 + caplen as usize].to_vec();
    Ok(Some(RawPacket {
        timestamp_secs: 0,
        timestamp_usecs: 0,
        orig_len: origlen,
        data,
    }))
}

fn split_timestamp(ts: u128, units_per_sec: u64) -> (u32, u32) {
    let units = u128::from(units_per_sec).max(1);
    let secs = ts / units;
    let frac = ts % units;
    let usecs = if units == 1_000_000 {
        frac
    } else if units >= 1_000_000 {
        // higher resolution → truncate to microseconds
        frac / (units / 1_000_000)
    } else {
        // coarser than us (e.g. ms): scale up
        frac * (1_000_000 / units)
    };
    (
        u32::try_from(secs).unwrap_or(u32::MAX),
        u32::try_from(usecs).unwrap_or(999_999).min(999_999),
    )
}

fn align4(n: usize) -> usize {
    n.wrapping_add(3) & !3
}

fn read_u32_endian(bytes: &[u8], little_endian: bool) -> u32 {
    let arr: [u8; 4] = bytes.try_into().unwrap_or([0, 0, 0, 0]);
    if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn read_u16_endian(bytes: &[u8], little_endian: bool) -> u16 {
    let arr: [u8; 2] = bytes.try_into().unwrap_or([0, 0]);
    if little_endian {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    }
}

fn read_u32(bytes: &[u8], swapped: bool) -> u32 {
    let arr: [u8; 4] = bytes.try_into().unwrap_or([0, 0, 0, 0]);
    if swapped {
        u32::from_be_bytes(arr)
    } else {
        u32::from_le_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    #[test]
    fn roundtrip_pcap_write_read() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        let pkt = RawPacket {
            timestamp_secs: 1_700_000_000,
            timestamp_usecs: 123_456,
            orig_len: 4,
            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };

        {
            let mut w = PcapWriter::create(path, 65535).unwrap();
            w.write_packet(&pkt).unwrap();
            w.flush().unwrap();
        }

        let mut src = OfflineSource::open(path).unwrap();
        let got = src.next_packet().unwrap().unwrap();
        assert_eq!(got.data, pkt.data);
        assert_eq!(got.timestamp_secs, pkt.timestamp_secs);
        assert_eq!(got.timestamp_usecs, pkt.timestamp_usecs);
        assert!(src.next_packet().unwrap().is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), [0u8; 24]).unwrap();
        assert!(OfflineSource::open(tmp.path()).is_err());
    }

    #[test]
    fn reads_pcapng_fixture() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dns_query.pcapng");
        let mut src = OfflineSource::open(&path).unwrap();
        let pkt = src.next_packet().unwrap().unwrap();
        assert_eq!(pkt.data.len(), 71);
        assert_eq!(pkt.timestamp_secs, 1_700_000_000);
        assert_eq!(pkt.timestamp_usecs, 0);
        assert!(src.next_packet().unwrap().is_none());
    }

    #[test]
    fn pcapng_matches_classic_payload() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut classic = OfflineSource::open(&root.join("dns_query.pcap")).unwrap();
        let mut ng = OfflineSource::open(&root.join("dns_query.pcapng")).unwrap();
        let a = classic.next_packet().unwrap().unwrap();
        let b = ng.next_packet().unwrap().unwrap();
        assert_eq!(a.data, b.data);
        assert_eq!(a.orig_len, b.orig_len);
        assert_eq!(a.timestamp_secs, b.timestamp_secs);
    }

    #[test]
    fn split_timestamp_microseconds() {
        let (s, u) = split_timestamp(1_700_000_000_123_456u128, 1_000_000);
        assert_eq!(s, 1_700_000_000);
        assert_eq!(u, 123_456);
    }

    #[test]
    fn read_global_header_cursor() {
        let mut buf = Vec::new();
        write_global_header(&mut buf, 65535).unwrap();
        let mut cur = Cursor::new(buf);
        let mut magic = [0u8; 4];
        cur.read_exact(&mut magic).unwrap();
        let (swapped, snap) = read_global_header_after_magic(&mut cur, magic).unwrap();
        assert!(!swapped);
        assert_eq!(snap, 65535);
    }
}
