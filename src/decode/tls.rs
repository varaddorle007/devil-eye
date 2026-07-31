//! Passive TLS handshake metadata (ClientHello / ServerHello only).
//!
//! Extracts record version, handshake type, optional SNI, selected cipher,
//! and JA3 ClientHello fingerprints. Does **not** decrypt application data.

use md5::{Digest, Md5};

use crate::packet::TlsInfo;

const CONTENT_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const EXT_SNI: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;

/// Record looks like a TLS handshake (0x16 0x03 …).
pub fn looks_like_tls(payload: &[u8]) -> bool {
    payload.len() >= 5
        && payload[0] == CONTENT_HANDSHAKE
        && payload[1] == 0x03
        && payload[2] <= 0x04
}

/// Decode TLS ClientHello / ServerHello metadata from the start of a TCP segment.
pub fn decode_tls(payload: &[u8]) -> Option<TlsInfo> {
    if !looks_like_tls(payload) {
        return None;
    }

    let record_version = format_tls_version(payload[1], payload[2]);
    let hs = &payload[5..];
    if hs.len() < 4 {
        return None;
    }
    let hs_type = hs[0];
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len.min(1) && hs.len() < 6 {
        return None;
    }
    let body = &hs[4..];

    match hs_type {
        HS_CLIENT_HELLO => decode_client_hello(body, record_version),
        HS_SERVER_HELLO => decode_server_hello(body, record_version),
        _ => Some(TlsInfo {
            handshake: format!("handshake_type_{hs_type}"),
            version: record_version,
            sni: None,
            cipher_suite: None,
            ja3: None,
            ja3_hash: None,
            ja3s: None,
            ja3s_hash: None,
        }),
    }
}

fn decode_client_hello(body: &[u8], record_version: String) -> Option<TlsInfo> {
    if body.len() < 34 {
        return None;
    }
    let version_u16 = u16::from_be_bytes([body[0], body[1]]);
    let hello_version = format_tls_version(body[0], body[1]);
    let version = prefer_version(hello_version, record_version);
    let mut i = 34; // version(2) + random(32)
    if body.len() < i + 1 {
        return None;
    }
    let sid_len = body[i] as usize;
    i += 1 + sid_len;
    if body.len() < i + 2 {
        return Some(partial_client_hello(version));
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + cs_len {
        return Some(partial_client_hello(version));
    }
    let mut ciphers = Vec::new();
    let mut j = 0;
    while j + 2 <= cs_len {
        let cs = u16::from_be_bytes([body[i + j], body[i + j + 1]]);
        if !is_grease(cs) {
            ciphers.push(cs);
        }
        j += 2;
    }
    i += cs_len;
    if body.len() < i + 1 {
        return Some(partial_client_hello(version));
    }
    let comp_len = body[i] as usize;
    i += 1 + comp_len;

    let mut sni = None;
    let mut ext_types = Vec::new();
    let mut curves = Vec::new();
    let mut ec_points = Vec::new();

    if body.len() >= i + 2 {
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        let ext_end = (i + ext_len).min(body.len());
        let exts = &body[i..ext_end];
        parse_extensions(exts, &mut sni, &mut ext_types, &mut curves, &mut ec_points);
    }

    let (ja3, ja3_hash) = build_ja3(version_u16, &ciphers, &ext_types, &curves, &ec_points);

    Some(TlsInfo {
        handshake: "client_hello".into(),
        version,
        sni,
        cipher_suite: None,
        ja3: Some(ja3),
        ja3_hash: Some(ja3_hash),
        ja3s: None,
        ja3s_hash: None,
    })
}

fn partial_client_hello(version: String) -> TlsInfo {
    TlsInfo {
        handshake: "client_hello".into(),
        version,
        sni: None,
        cipher_suite: None,
        ja3: None,
        ja3_hash: None,
        ja3s: None,
        ja3s_hash: None,
    }
}

fn decode_server_hello(body: &[u8], record_version: String) -> Option<TlsInfo> {
    if body.len() < 34 {
        return None;
    }
    let version_u16 = u16::from_be_bytes([body[0], body[1]]);
    let hello_version = format_tls_version(body[0], body[1]);
    let version = prefer_version(hello_version, record_version);
    let mut i = 34;
    if body.len() < i + 1 {
        return None;
    }
    let sid_len = body[i] as usize;
    i += 1 + sid_len;
    if body.len() < i + 2 {
        return Some(TlsInfo {
            handshake: "server_hello".into(),
            version,
            sni: None,
            cipher_suite: None,
            ja3: None,
            ja3_hash: None,
            ja3s: None,
            ja3s_hash: None,
        });
    }
    let cipher_u16 = u16::from_be_bytes([body[i], body[i + 1]]);
    let cipher = Some(format!("0x{cipher_u16:04x}"));
    i += 2;
    if body.len() < i + 1 {
        return Some(TlsInfo {
            handshake: "server_hello".into(),
            version,
            sni: None,
            cipher_suite: cipher,
            ja3: None,
            ja3_hash: None,
            ja3s: None,
            ja3s_hash: None,
        });
    }
    // compression method (1 byte)
    i += 1;

    let mut ext_types = Vec::new();
    if body.len() >= i + 2 {
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        let ext_end = (i + ext_len).min(body.len());
        collect_extension_types(&body[i..ext_end], &mut ext_types);
    }

    let (ja3s, ja3s_hash) = build_ja3s(version_u16, cipher_u16, &ext_types);

    Some(TlsInfo {
        handshake: "server_hello".into(),
        version,
        sni: None,
        cipher_suite: cipher,
        ja3: None,
        ja3_hash: None,
        ja3s: Some(ja3s),
        ja3s_hash: Some(ja3s_hash),
    })
}

fn prefer_version(hello: String, record: String) -> String {
    if hello == "unknown" {
        record
    } else {
        hello
    }
}

fn parse_extensions(
    exts: &[u8],
    sni: &mut Option<String>,
    ext_types: &mut Vec<u16>,
    curves: &mut Vec<u16>,
    ec_points: &mut Vec<u8>,
) {
    let mut i = 0;
    while i + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let len = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        i += 4;
        if i + len > exts.len() {
            break;
        }
        let data = &exts[i..i + len];
        if !is_grease(typ) {
            ext_types.push(typ);
        }
        match typ {
            EXT_SNI if sni.is_none() => {
                *sni = parse_sni_data(data);
            }
            EXT_SUPPORTED_GROUPS => {
                parse_supported_groups(data, curves);
            }
            EXT_EC_POINT_FORMATS => {
                parse_ec_point_formats(data, ec_points);
            }
            _ => {}
        }
        i += len;
    }
}

fn collect_extension_types(exts: &[u8], ext_types: &mut Vec<u16>) {
    let mut i = 0;
    while i + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let len = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        i += 4;
        if i + len > exts.len() {
            break;
        }
        if !is_grease(typ) {
            ext_types.push(typ);
        }
        i += len;
    }
}

fn parse_sni_data(data: &[u8]) -> Option<String> {
    // server_name list length (2) + name_type (1) + name_len (2) + name
    if data.len() >= 5 {
        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() >= 5 + name_len && data[2] == 0 {
            if let Ok(name) = std::str::from_utf8(&data[5..5 + name_len]) {
                if !name.is_empty() && name.len() <= 253 {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

fn parse_supported_groups(data: &[u8], out: &mut Vec<u16>) {
    if data.len() < 2 {
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (2 + list_len).min(data.len());
    let mut i = 2;
    while i + 2 <= end {
        let g = u16::from_be_bytes([data[i], data[i + 1]]);
        if !is_grease(g) {
            out.push(g);
        }
        i += 2;
    }
}

fn parse_ec_point_formats(data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    let n = data[0] as usize;
    let end = (1 + n).min(data.len());
    out.extend_from_slice(&data[1..end]);
}

/// RFC 8701 GREASE values (both bytes equal, low nibble 0xa).
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

fn join_u16(vals: &[u16]) -> String {
    vals.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(vals: &[u8]) -> String {
    vals.iter()
        .map(|v| (*v).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Build JA3 string + MD5 hash (Salesforce JA3 format).
pub fn build_ja3(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    ec_points: &[u8],
) -> (String, String) {
    let ciphers: Vec<u16> = ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
    let extensions: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let curves: Vec<u16> = curves.iter().copied().filter(|v| !is_grease(*v)).collect();
    let ja3 = format!(
        "{version},{},{},{},{}",
        join_u16(&ciphers),
        join_u16(&extensions),
        join_u16(&curves),
        join_u8(ec_points)
    );
    let mut hasher = Md5::new();
    hasher.update(ja3.as_bytes());
    let digest = hasher.finalize();
    let hash = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (ja3, hash)
}

/// Build JA3S string + MD5 hash (`Version,Cipher,Extensions`).
pub fn build_ja3s(version: u16, cipher: u16, extensions: &[u16]) -> (String, String) {
    let extensions: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let ja3s = format!("{version},{cipher},{}", join_u16(&extensions));
    let mut hasher = Md5::new();
    hasher.update(ja3s.as_bytes());
    let digest = hasher.finalize();
    let hash = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (ja3s, hash)
}

fn format_tls_version(major: u8, minor: u8) -> String {
    match (major, minor) {
        (0x03, 0x00) => "SSL3".into(),
        (0x03, 0x01) => "TLS1.0".into(),
        (0x03, 0x02) => "TLS1.1".into(),
        (0x03, 0x03) => "TLS1.2".into(),
        (0x03, 0x04) => "TLS1.3".into(),
        _ => "unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // version TLS1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session id len
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // one cipher TLS_RSA_WITH_AES_128_CBC_SHA
        hello.push(1);
        hello.push(0); // null compression

        let mut exts = Vec::new();
        // SNI
        let name = sni.as_bytes();
        let list_len = (1 + 2 + name.len()) as u16;
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&EXT_SNI.to_be_bytes());
        let ext_data_len = (2 + list_len as usize) as u16;
        sni_ext.extend_from_slice(&ext_data_len.to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        exts.extend_from_slice(&sni_ext);

        // supported_groups: 0x0017 (secp256r1)
        let mut groups = Vec::new();
        groups.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        groups.extend_from_slice(&4u16.to_be_bytes()); // data len
        groups.extend_from_slice(&2u16.to_be_bytes()); // list len
        groups.extend_from_slice(&0x0017u16.to_be_bytes());
        exts.extend_from_slice(&groups);

        // ec_point_formats: uncompressed (0)
        let mut points = Vec::new();
        points.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        points.extend_from_slice(&2u16.to_be_bytes());
        points.push(1);
        points.push(0);
        exts.extend_from_slice(&points);

        hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&exts);

        let hs_len = hello.len();
        let mut hs = vec![
            HS_CLIENT_HELLO,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let pkt = build_client_hello_with_sni("example.com");
        let info = decode_tls(&pkt).expect("tls");
        assert_eq!(info.handshake, "client_hello");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert!(info.version.contains("TLS"));
    }

    #[test]
    fn computes_ja3_for_client_hello() {
        let pkt = build_client_hello_with_sni("example.com");
        let info = decode_tls(&pkt).expect("tls");
        let ja3 = info.ja3.as_deref().expect("ja3");
        // TLS1.2=771, cipher 47, exts 0-10-11, curve 23, point 0
        assert_eq!(ja3, "771,47,0-10-11,23,0");
        let hash = info.ja3_hash.as_deref().expect("ja3_hash");
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable hash for this synthetic hello
        let (s, h) = build_ja3(771, &[47], &[0, 10, 11], &[23], &[0]);
        assert_eq!(ja3, s);
        assert_eq!(hash, h);
    }

    #[test]
    fn grease_filtered_from_ja3() {
        let (ja3, _) = build_ja3(771, &[0x0a0a, 47, 0x1a1a], &[0x0a0a, 0, 10], &[23], &[0]);
        assert_eq!(ja3, "771,47,0-10,23,0");
    }

    #[test]
    fn parses_server_hello_cipher() {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0xc0, 0x2f]); // cipher
        hello.push(0); // compression
                       // extensions: renegotiation_info (0xff01) empty-ish + ec_point_formats
        let mut exts = Vec::new();
        exts.extend_from_slice(&0xff01u16.to_be_bytes());
        exts.extend_from_slice(&1u16.to_be_bytes());
        exts.push(0);
        exts.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.push(1);
        exts.push(0);
        hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&exts);

        let hs_len = hello.len();
        let mut hs = vec![
            HS_SERVER_HELLO,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&hello);

        let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        let info = decode_tls(&record).expect("tls");
        assert_eq!(info.handshake, "server_hello");
        assert_eq!(info.cipher_suite.as_deref(), Some("0xc02f"));
        assert!(info.ja3.is_none());
        let ja3s = info.ja3s.as_deref().expect("ja3s");
        assert_eq!(ja3s, "771,49199,65281-11");
        assert_eq!(info.ja3s_hash.as_ref().map(|h| h.len()), Some(32));
        let (s, h) = build_ja3s(771, 0xc02f, &[0xff01, 11]);
        assert_eq!(ja3s, s);
        assert_eq!(info.ja3s_hash.as_deref(), Some(h.as_str()));
    }
}
