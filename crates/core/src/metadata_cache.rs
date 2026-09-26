// User-owned cache of SAFE config metadata (endpoint, addresses, DNS...).
//
// Why it exists: /etc/wireguard is 0700 root-only (we enforce that ourselves),
// so the unprivileged GUI cannot read configs back to display a friendly name.
// Instead, at import time we persist only [`SafeConfigMetadata`] — which by
// construction contains no private or preshared keys — to this file.
use crate::models::SafeConfigMetadata;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn path() -> PathBuf {
    crate::logging::state_dir().join("configs.json")
}

fn load_all() -> BTreeMap<String, SafeConfigMetadata> {
    load_from(&path())
}

/// Load from an explicit path (testable without touching XDG_STATE_HOME).
pub(crate) fn load_from(p: &std::path::Path) -> BTreeMap<String, SafeConfigMetadata> {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Metadata for every installed config we know about.
pub fn all() -> BTreeMap<String, SafeConfigMetadata> {
    load_all()
}

/// Best-effort lookup by tunnel name.
pub fn get(name: &str) -> Option<SafeConfigMetadata> {
    load_all().get(name).cloned()
}

/// Record (or replace) metadata for one tunnel. Called after a successful
/// install; failures are non-fatal because it is only a display cache.
pub fn store(meta: &SafeConfigMetadata) {
    store_to(&path(), meta);
}

/// Drop a tunnel's cached metadata (after delete).
pub fn forget(name: &str) {
    forget_at(&path(), name);
}

/// Insert into `p` (testable without touching XDG_STATE_HOME).
pub(crate) fn store_to(p: &std::path::Path, meta: &SafeConfigMetadata) {
    let mut map = load_from(p);
    map.insert(meta.name.clone(), meta.clone());
    write_to(p, &map);
}

pub(crate) fn forget_at(p: &std::path::Path, name: &str) {
    let mut map = load_from(p);
    if map.remove(name).is_some() {
        write_to(p, &map);
    }
}

fn write_to(p: &std::path::Path, map: &BTreeMap<String, SafeConfigMetadata>) {
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let json = match serde_json::to_string_pretty(map) {
        Ok(j) => j,
        Err(_) => return,
    };
    if std::fs::write(p, json).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> SafeConfigMetadata {
        SafeConfigMetadata {
            name: name.to_string(),
            display_name: format!("{name} display"),
            endpoint_host: "193.32.127.66".to_string(),
            endpoint_port: 51820,
            addresses: vec!["10.64.0.5/32".to_string()],
            dns: vec!["10.64.0.1".to_string()],
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            kill_switch_detected: false,
            hook_commands: vec![],
            hooks_look_risky: false,
            provider_hint: Some("mullvad".to_string()),
        }
    }

    #[test]
    fn round_trip_cache() {
        let p = std::env::temp_dir().join(format!(
            "mullvad-helper-cache-test-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&p);
        store_to(&p, &sample("t1"));
        let got = load_from(&p).remove("t1").expect("cached metadata survives");
        assert_eq!(got.endpoint_host, "193.32.127.66");
        assert_eq!(got.provider_hint.as_deref(), Some("mullvad"));
        assert_eq!(got.endpoint_port, 51820);
        // The cache must never carry key material.
        let raw = std::fs::read_to_string(&p).unwrap_or_default();
        let lower = raw.to_lowercase();
        assert!(!lower.contains("privatekey"));
        assert!(!lower.contains("preshared"));
        forget_at(&p, "t1");
        assert!(load_from(&p).get("t1").is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_is_empty_not_an_error() {
        let p = std::env::temp_dir().join("mullvad-helper-cache-definitely-missing.json");
        let _ = std::fs::remove_file(&p);
        assert!(load_from(&p).is_empty());
    }
}
