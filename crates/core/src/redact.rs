// Secret redaction for logs and diagnostics.
//!
//! Replaces the value of `PrivateKey` / `PresharedKey` anywhere in the text
//! (not just at the start of a line) with `[REDACTED]`. This matters because
//! wg-quick and `wg showconf` output frequently embeds these mid-line, e.g.
//! `ERROR unable to parse PrivateKey = <secret>`.

use regex::Regex;
use std::sync::OnceLock;

/// Matches `privatekey`/`presharedkey` (any case) then `= value` until
/// whitespace, semicolon or end of line — wherever it appears in the text.
fn key_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(privatekey|presharedkey)\s*=\s*[^\s;]+").unwrap()
    })
}

/// Redact key material from arbitrary text (config dumps, command output).
pub fn redact_secrets(input: &str) -> String {
    key_regex()
        .replace_all(input, |caps: &regex::Captures| {
            format!("{} = [REDACTED]", &caps[1])
        })
        .to_string()
}

/// Check whether a string still appears to contain key material (for tests).
pub fn looks_like_key(value: &str) -> bool {
    let v = value.trim();
    v.len() >= 40 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_both_key_types() {
        let input = "[Interface]\nPrivateKey = ABCDEFGH1234567890ABCDEFGHIJ1234567890AB=\n[Peer]\nPresharedKey=XYZ1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ=\nEndpoint=1.2.3.4:51820\n";
        let out = redact_secrets(input);
        assert!(!out.contains("ABCDEFGH"));
        assert!(!out.contains("XYZ123"));
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("1.2.3.4:51820"));
    }

    #[test]
    fn leaves_safe_metadata_alone() {
        let input = "Endpoint = 193.32.127.66:51820\nAddress = 10.64.0.5/32\n";
        assert_eq!(redact_secrets(input), input);
    }

    /// Regression: keys embedded in the middle of a log line must be redacted.
    #[test]
    fn redacts_keys_embedded_mid_line() {
        let input = "ERROR wg-quick failed: PrivateKey = SECRET1234567890SECRET1234567890SECRET= (exit 1)";
        let out = redact_secrets(input);
        assert!(!out.contains("SECRET1234"), "leaked: {out}");
        assert!(out.contains("PrivateKey = [REDACTED]"));
        assert!(out.contains("(exit 1)"));
    }

    #[test]
    fn redacts_config_dump_indented_and_quoted() {
        let dump = "  privatekey=QUOTEDSECRET1234567890ABCDEFGHIJKLMNOPQRSTUV=\tpresharedkey=none";
        let out = redact_secrets(dump);
        assert!(!out.contains("QUOTEDSECRET"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn looks_like_key_heuristic() {
        assert!(looks_like_key("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcd="));
        assert!(!looks_like_key("10.64.0.5/32"));
    }
}

