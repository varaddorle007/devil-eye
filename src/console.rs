//! Interactive module picker console.

use std::io::{self, BufRead, Write};

use anyhow::Result;

use crate::banner;

/// One selectable console action.
struct MenuItem {
    key: &'static str,
    summary: &'static str,
    /// Example line shown after selection (user can edit / retype).
    example: &'static str,
}

const MENU: &[MenuItem] = &[
    MenuItem {
        key: "capture",
        summary: "Passive PCAP replay / live sniff (tcpdump-class)",
        example: "capture -r tests/fixtures/dns_query.pcap --stats",
    },
    MenuItem {
        key: "detect",
        summary: "IDS-lite alerts on a capture",
        example: "detect -r tests/fixtures/mixed.pcap --json-out alerts.json",
    },
    MenuItem {
        key: "watch",
        summary: "Live terminal / HTML dashboard",
        example: "watch -r tests/fixtures/mixed.pcap --no-clear",
    },
    MenuItem {
        key: "scan",
        summary: "Authorized TCP/UDP probe (scope REQUIRED; --proto tcp|udp|both)",
        example: "scan --scope examples/scope.lab.json --proto both --json-out scan-report.json",
    },
    MenuItem {
        key: "enum",
        summary: "Banners + TLS cert metadata (scope REQUIRED)",
        example: "enum --scope examples/scope.lab.json --json-out enum-report.json",
    },
    MenuItem {
        key: "merge",
        summary: "Merge PCAP/PCAPNG files by time",
        example: "merge -w combined.pcap tests/fixtures/dns_query.pcap tests/fixtures/http_get.pcap",
    },
    MenuItem {
        key: "slice",
        summary: "Cut a capture by Unix-time window",
        example: "slice -r combined.pcap -w window.pcap --after 1700000000 --before 1700000100",
    },
    MenuItem {
        key: "diff",
        summary: "Compare two detect alert JSON reports",
        example: "diff --before baseline.json --after alerts.json",
    },
    MenuItem {
        key: "import",
        summary: "Import Suricata EVE / Zeek logs",
        example: "import --eve examples/eve.sample.jsonl --json-out eve-alerts.json -v",
    },
    MenuItem {
        key: "export",
        summary: "Export detect JSON to SIEM formats",
        example: "export --detect-json alerts.json --siem-out alerts.cef --siem-format cef",
    },
    MenuItem {
        key: "report",
        summary: "Build Markdown/HTML evidence pack",
        example: "report --detect-json alerts.json --out-md report.md --template executive",
    },
    MenuItem {
        key: "session",
        summary: "Multi-operator engagement sessions",
        example: "session status --scope examples/scope.lab.json --session-dir ./sessions/lab1",
    },
    MenuItem {
        key: "modules",
        summary: "Print full module catalog",
        example: "modules",
    },
];

/// Print numbered menu to stdout.
pub fn print_menu(use_color: bool) {
    let (bold, reset) = if use_color {
        ("\x1b[1m", "\x1b[0m")
    } else {
        ("", "")
    };
    println!("{bold}Modules — pick a number (or type the name):{reset}");
    println!();
    for (i, item) in MENU.iter().enumerate() {
        println!(
            "  {bold}[{:>2}]{reset} {:<10}  {}",
            i + 1,
            item.key,
            item.summary
        );
    }
    println!();
    println!("  {bold}[ q]{reset} quit");
    println!();
}

/// Run the interactive picker. Returns the argv tokens to re-dispatch, or None to exit.
pub fn prompt_selection(use_color: bool) -> Result<Option<Vec<String>>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    print_menu(use_color);

    loop {
        write!(stdout, "devil-eye > ")?;
        stdout.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let choice = line.trim();
        if choice.is_empty() {
            continue;
        }
        let lower = choice.to_ascii_lowercase();
        if matches!(lower.as_str(), "q" | "quit" | "exit") {
            return Ok(None);
        }
        if matches!(lower.as_str(), "help" | "?" | "menu" | "h") {
            print_menu(use_color);
            continue;
        }

        let item = if let Ok(n) = choice.parse::<usize>() {
            MENU.get(n.saturating_sub(1))
        } else {
            MENU.iter().find(|m| m.key.eq_ignore_ascii_case(choice))
        };

        let Some(item) = item else {
            eprintln!("unknown selection '{choice}' — type a number, name, help, or q");
            continue;
        };

        eprintln!();
        eprintln!("Selected: {} — {}", item.key, item.summary);
        eprintln!("Example:  {}", item.example);
        eprintln!("Press Enter to run the example, or type a full command line:");
        write!(stdout, "devil-eye > ")?;
        stdout.flush()?;

        let mut cmd_line = String::new();
        if stdin.lock().read_line(&mut cmd_line)? == 0 {
            return Ok(None);
        }
        let cmd_line = cmd_line.trim();
        let final_line = if cmd_line.is_empty() {
            item.example
        } else {
            cmd_line
        };

        let tokens = shell_split(final_line);
        if tokens.is_empty() {
            continue;
        }
        return Ok(Some(tokens));
    }
}

/// Show banner + menu once (non-loop helper for tests / docs).
pub fn show_splash(no_banner: bool, use_color: bool) {
    banner::maybe_print(no_banner, use_color);
    print_menu(use_color);
}

/// Naive shell-ish split (handles simple double quotes).
fn shell_split(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_handles_quotes() {
        let t = shell_split(r#"capture -f "udp port 53" -r x.pcap"#);
        assert_eq!(t, vec!["capture", "-f", "udp port 53", "-r", "x.pcap"]);
    }

    #[test]
    fn menu_has_capture_first() {
        assert_eq!(MENU[0].key, "capture");
    }
}
