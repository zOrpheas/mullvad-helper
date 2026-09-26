//! WireGuard .conf parser: validation + safe metadata only.
//! Never returns key material; see SafeConfigMetadata docs.

use crate::models::SafeConfigMetadata;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireGuardParseError {
    #[error("missing [Interface] section")]
    MissingInterface,
    #[error("missing [Peer] section (at least one peer is required)")]
    MissingPeer,
    #[error("missing PrivateKey in [Interface]")]
    MissingPrivateKey,
    #[error("[Interface] Address is missing (e.g. Address = 10.64.0.5/32)")]
    MissingAddress,
    #[error("[Peer] PublicKey is missing")]
    MissingPublicKey,
    #[error("[Peer] Endpoint is missing (e.g. Endpoint = 193.32.127.66:51820)")]
    MissingEndpoint,
    #[error("malformed Endpoint '{0}' (expected host:port)")]
    MalformedEndpoint(String),
    #[error("invalid tunnel name '{0}' (use only letters, numbers, - and _, max 15 chars)")]
    InvalidName(String),
    #[error("empty configuration file")]
    Empty,
}

#[derive(Debug, Clone)]
pub struct ParsedConfig {
    pub metadata: SafeConfigMetadata,
    pub has_private_key: bool,
    pub has_public_key: bool,
}

/// Validate a tunnel/interface name for wg-quick + systemd (max 15 chars).
pub fn validate_tunnel_name(name: &str) -> Result<(), WireGuardParseError> {
    if name.is_empty() || name.len() > 15 {
        return Err(WireGuardParseError::InvalidName(name.to_string()));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        return Err(WireGuardParseError::InvalidName(name.to_string()));
    }
    Ok(())
}

/// Derive a tunnel name from a file name and validate it.
pub fn tunnel_name_from_filename(filename: &str) -> Result<String, WireGuardParseError> {
    let base = filename.rsplit('/').next().unwrap_or(filename);
    let stem = base.strip_suffix(".conf").unwrap_or(base);
    validate_tunnel_name(stem)?;
    Ok(stem.to_string())
}

fn parse_endpoint(raw: &str) -> Result<(String, u16), WireGuardParseError> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let after = rest[end + 1..].trim();
            let port_str = after.strip_prefix(':').unwrap_or("").trim();
            if host.is_empty() || port_str.is_empty() {
                return Err(WireGuardParseError::MalformedEndpoint(raw.to_string()));
            }
            let port: u16 = port_str
                .parse()
                .map_err(|_| WireGuardParseError::MalformedEndpoint(raw.to_string()))?;
            return Ok((host, port));
        }
        return Err(WireGuardParseError::MalformedEndpoint(raw.to_string()));
    }
    if let Some(colon) = raw.rfind(':') {
        let host = raw[..colon].trim().to_string();
        let port_str = raw[colon + 1..].trim();
        if host.is_empty() || port_str.is_empty() {
            return Err(WireGuardParseError::MalformedEndpoint(raw.to_string()));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| WireGuardParseError::MalformedEndpoint(raw.to_string()))?;
        return Ok((host, port));
    }
    Err(WireGuardParseError::MalformedEndpoint(raw.to_string()))
}

/// Heuristic: nftables/iptables rules dropping everything except the tunnel.
pub(crate) fn is_kill_switch_rule(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let has_fwmark = lower.contains("fwmark");
    let has_drop = lower.contains("drop") || lower.contains("reject");
    let has_nft = lower.contains("nft");
    let has_iptables = lower.contains("iptables");
    (has_nft || has_iptables) && (has_fwmark || has_drop)
}

/// Hooks run as root via wg-quick: flag shell chaining/substitution.
pub(crate) fn looks_risky_hook(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    cmd.contains(';')
        || cmd.contains('`')
        || cmd.contains('$')
        || cmd.contains('|')
        || lower.contains("&&")
        || lower.contains("||")
}

fn detect_provider(endpoint: &str) -> Option<String> {
    if endpoint.to_lowercase().contains("mullvad") {
        return Some("mullvad".to_string());
    }
    None
}

/// Turn `de-fra-wg-001` into `Germany — Frankfurt` when recognizable.
pub fn prettify_tunnel_name(stem: &str) -> String {
    let city = |code: &str| -> Option<&'static str> {
        match code {
            "fra" => Some("Frankfurt"),
            "ber" => Some("Berlin"),
            "mma" => Some("Malmö"),
            "sto" => Some("Stockholm"),
            "got" => Some("Gothenburg"),
            "ams" => Some("Amsterdam"),
            "par" => Some("Paris"),
            "lhr" | "lon" => Some("London"),
            "nyc" => Some("New York"),
            "lax" => Some("Los Angeles"),
            "syd" => Some("Sydney"),
            "tok" | "tyo" => Some("Tokyo"),
            "zur" => Some("Zurich"),
            _ => None,
        }
    };
    let country = |code: &str| -> Option<&'static str> {
        match code {
            "de" => Some("Germany"),
            "se" => Some("Sweden"),
            "nl" => Some("Netherlands"),
            "fr" => Some("France"),
            "gb" | "uk" => Some("United Kingdom"),
            "us" => Some("United States"),
            "au" => Some("Australia"),
            "jp" => Some("Japan"),
            "ch" => Some("Switzerland"),
            _ => None,
        }
    };
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() >= 2 {
        if let (Some(c), Some(ct)) = (country(parts[0]), city(parts[1])) {
            return format!("{c} — {ct}");
        }
    }
    stem.replace(['-', '_'], " ")
}

/// Parse a WireGuard .conf body. `fallback_name` = file stem for display.
/// Returns ONLY safe metadata; key material is validated but never returned.
pub fn parse_wireguard_config(
    text: &str,
    fallback_name: &str,
) -> Result<ParsedConfig, WireGuardParseError> {
    use std::collections::HashMap;
    if text.trim().is_empty() {
        return Err(WireGuardParseError::Empty);
    }
    let mut sections: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut current: Option<String> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_lowercase();
            current = Some(name.clone());
            sections.entry(name).or_default();
            continue;
        }
        let Some(section) = current.clone() else {
            continue;
        };
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_lowercase();
            let value = line[eq + 1..].trim().to_string();
            if let Some(v) = sections.get_mut(&section) {
                v.push((key, value));
            }
        }
    }
    let iface = sections
        .get("interface")
        .ok_or(WireGuardParseError::MissingInterface)?;
    if iface.is_empty() {
        return Err(WireGuardParseError::MissingInterface);
    }
    let mut all_peers: Vec<Vec<(String, String)>> = Vec::new();
    {
        let mut cur = String::new();
        let mut acc: Vec<(String, String)> = Vec::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                if cur == "peer" && !acc.is_empty() {
                    all_peers.push(std::mem::take(&mut acc));
                }
                cur = line[1..line.len() - 1].trim().to_lowercase();
                continue;
            }
            if cur == "peer" {
                if let Some(eq) = line.find('=') {
                    acc.push((
                        line[..eq].trim().to_lowercase(),
                        line[eq + 1..].trim().to_string(),
                    ));
                }
            }
        }
        if cur == "peer" && !acc.is_empty() {
            all_peers.push(acc);
        }
    }
    if all_peers.is_empty() {
        return Err(WireGuardParseError::MissingPeer);
    }
    let mut peer_flat: Vec<(String, String)> = Vec::new();
    for p in &all_peers {
        peer_flat.extend(p.clone());
    }
    let first = |pairs: &[(String, String)], key: &str| -> Option<String> {
        pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    let all = |pairs: &[(String, String)], key: &str| -> Vec<String> {
        pairs
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let private_key = first(iface, "privatekey").unwrap_or_default();
    if private_key.trim().is_empty() {
        return Err(WireGuardParseError::MissingPrivateKey);
    }
    let address_raw = first(iface, "address").unwrap_or_default();
    if address_raw.trim().is_empty() {
        return Err(WireGuardParseError::MissingAddress);
    }
    let public_key = first(&peer_flat, "publickey").unwrap_or_default();
    if public_key.trim().is_empty() {
        return Err(WireGuardParseError::MissingPublicKey);
    }
    let endpoint_raw = first(&peer_flat, "endpoint").unwrap_or_default();
    if endpoint_raw.trim().is_empty() {
        return Err(WireGuardParseError::MissingEndpoint);
    }
    let (endpoint_host, endpoint_port) = parse_endpoint(&endpoint_raw)?;
    let split_csv = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };
    let addresses: Vec<String> = address_raw
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    let dns = split_csv(&first(iface, "dns").unwrap_or_default());
    let allowed_ips = split_csv(&first(&peer_flat, "allowedips").unwrap_or_default());
    let mut hook_commands: Vec<String> = Vec::new();
    for key in ["postup", "predown", "preup", "postdown"] {
        for v in all(iface, key) {
            hook_commands.push(format!("{key} = {v}"));
        }
    }
    let kill_switch_detected = hook_commands.iter().any(|c| is_kill_switch_rule(c));
    let hooks_look_risky = hook_commands.iter().any(|c| looks_risky_hook(c));
    let provider_hint = detect_provider(&endpoint_raw);
    let display_name = prettify_tunnel_name(fallback_name);
    Ok(ParsedConfig {
        metadata: SafeConfigMetadata {
            name: fallback_name.to_string(),
            display_name,
            endpoint_host,
            endpoint_port,
            addresses,
            dns,
            allowed_ips,
            kill_switch_detected,
            hook_commands,
            hooks_look_risky,
            provider_hint,
        },
        has_private_key: true,
        has_public_key: true,
    })
}

