//! SSH identification string decoder (banner only — no auth material).

use crate::packet::SshInfo;

/// Heuristic: payload begins with an SSH protocol identification string.
pub fn looks_like_ssh(payload: &[u8]) -> bool {
    payload.starts_with(b"SSH-1.") || payload.starts_with(b"SSH-2.")
}

/// Parse the first line of an SSH identification string (`SSH-2.0-OpenSSH_…`).
pub fn decode_ssh(payload: &[u8]) -> Option<SshInfo> {
    if !looks_like_ssh(payload) {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    let line = text.lines().next()?.trim_end_matches(['\r', '\n']);
    if line.len() < 7 || line.len() > 255 {
        return None;
    }
    if !line.starts_with("SSH-1.") && !line.starts_with("SSH-2.") {
        return None;
    }
    let proto = if line.starts_with("SSH-1.") {
        "1.x"
    } else {
        "2.0"
    };
    Some(SshInfo {
        banner: line.to_string(),
        proto: proto.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openssh_banner() {
        let raw = b"SSH-2.0-OpenSSH_9.6\r\n";
        let info = decode_ssh(raw).expect("ssh");
        assert_eq!(info.proto, "2.0");
        assert!(info.banner.contains("OpenSSH_9.6"));
    }

    #[test]
    fn rejects_non_ssh() {
        assert!(decode_ssh(b"GET / HTTP/1.1\r\n").is_none());
    }
}
