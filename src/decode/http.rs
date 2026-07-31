//! Plaintext HTTP metadata decoder (no body dumping).

use crate::packet::HttpInfo;

const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Heuristic: starts like an HTTP request or response line.
pub fn looks_like_http(payload: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(payload) else {
        return false;
    };
    let line = text.lines().next().unwrap_or("");
    is_request_line(line) || is_status_line(line)
}

fn is_request_line(line: &str) -> bool {
    let methods = [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    ];
    methods.iter().any(|m| line.starts_with(m)) && line.contains("HTTP/")
}

fn is_status_line(line: &str) -> bool {
    line.starts_with("HTTP/1.") || line.starts_with("HTTP/2")
}

/// Decode plaintext HTTP start-line + Host (sensitive headers redacted).
pub fn decode_http(payload: &[u8]) -> Option<HttpInfo> {
    let text = std::str::from_utf8(payload).ok()?;
    // Limit scan window — avoid treating binary as huge strings.
    let window = if text.len() > 4096 {
        &text[..4096]
    } else {
        text
    };

    if window.contains("\r\n") {
        let mut parts = window.split("\r\n");
        let start = parts.next()?;
        if start.is_empty() {
            return None;
        }
        finish_http(start, parts)
    } else {
        let mut lf = window.split('\n');
        let start = lf.next()?.trim_end_matches('\r');
        if start.is_empty() {
            return None;
        }
        finish_http(start, lf.map(|l| l.trim_end_matches('\r')))
    }
}

fn finish_http<'a>(start: &str, headers: impl Iterator<Item = &'a str>) -> Option<HttpInfo> {
    if !(is_request_line(start) || is_status_line(start)) {
        return None;
    }

    let mut host = None;
    let mut has_authorization = false;
    for line in headers.take(64) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let lname = name.trim().to_ascii_lowercase();
            if lname == "host" {
                host = Some(escape_control(value.trim()));
            } else if lname == "authorization" || lname == "proxy-authorization" {
                has_authorization = true;
                // Intentionally ignore sensitive header values.
            } else if SENSITIVE_HEADERS.contains(&lname.as_str()) {
                // Intentionally ignore sensitive header values.
            }
        }
    }

    let method_or_status = if is_status_line(start) {
        start.split_whitespace().nth(1).unwrap_or("?").to_string()
    } else {
        start.split_whitespace().next().unwrap_or("?").to_string()
    };

    Some(HttpInfo {
        summary: escape_control(start),
        host,
        method_or_status,
        has_authorization,
    })
}

use std::fmt::Write as _;

fn escape_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars().take(200) {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    if s.chars().count() > 200 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_with_host() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAuthorization: secret\r\n\r\n";
        let info = decode_http(raw).unwrap();
        assert_eq!(info.method_or_status, "GET");
        assert_eq!(info.host.as_deref(), Some("example.com"));
        assert!(info.has_authorization);
        assert!(!info.summary.to_lowercase().contains("secret"));
    }

    #[test]
    fn status_line() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let info = decode_http(raw).unwrap();
        assert_eq!(info.method_or_status, "200");
    }

    #[test]
    fn rejects_binary() {
        assert!(decode_http(&[0xff, 0xfe, 0x00]).is_none());
    }
}
