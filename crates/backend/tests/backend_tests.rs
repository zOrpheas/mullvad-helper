//! Tests for non-UI backends with a mocked CommandRunner.
use std::sync::Arc;
use mullvad_helper_backend::command::{MockRunner, ok, fail};
use mullvad_helper_backend::deps::DepsService;
use mullvad_helper_backend::dns::DnsService;
use mullvad_helper_backend::wireguard::{health_from, parse_wg_dump};

#[tokio::test]
async fn dns_detects_systemd_resolved_with_openresolv_conflict() {
    let m = MockRunner::new();
    m.stub("systemctl", &["is-active", "systemd-resolved.service"], ok("active\n"));
    m.stub("systemctl", &["is-active", "NetworkManager.service"], fail(3, "inactive\n"));
    m.stub("readlink", &["/etc/resolv.conf"], ok("/run/systemd/resolve/stub-resolv.conf\n"));
    m.stub("sh", &["-c", "command -v resolvconf"], ok("/usr/bin/resolvconf\n"));
    m.stub("pacman", &["-Qo", "/usr/bin/resolvconf"], ok("/usr/bin/resolvconf is owned by openresolv 3.12.0-1\n"));
    m.stub("sh", &["-c", "resolvconf --version"], ok("openresolv 3.12.0\n"));
    let svc = DnsService::new(Arc::new(m));
    let info = svc.detect().await;
    assert_eq!(info.architecture, mullvad_helper_core::DnsArchitecture::SystemdResolvedWithIncompatibleResolvconf);
    assert!(info.problem.is_some());
    assert!(DnsService::<MockRunner>::suggested_resolvconf_fix(&info).is_some());
}

#[tokio::test]
async fn dns_detects_plain_openresolv() {
    let m = MockRunner::new();
    m.stub("systemctl", &["is-active", "systemd-resolved.service"], fail(3, "inactive\n"));
    m.stub("systemctl", &["is-active", "NetworkManager.service"], fail(3, "inactive\n"));
    m.stub("readlink", &["/etc/resolv.conf"], ok("/run/openresolv/resolv.conf\n"));
    m.stub("sh", &["-c", "command -v resolvconf"], ok("/usr/bin/resolvconf\n"));
    m.stub("pacman", &["-Qo", "/usr/bin/resolvconf"], ok("/usr/bin/resolvconf is owned by openresolv 3.12.0-1\n"));
    let svc = DnsService::new(Arc::new(m));
    let info = svc.detect().await;
    assert_eq!(info.architecture, mullvad_helper_core::DnsArchitecture::Openresolv);
    assert!(info.problem.is_none());
}

#[test]
fn wg_dump_parses_handshake_and_traffic() {
    // iface line + one peer with handshake 120s ago (fake epoch math tolerant).
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let hs = now - 8;
    let dump = format!("private-key\tpublic\t51820\toff\nPEERPUB\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t{hs}\t1234\t5678\toff\n");
    let st = parse_wg_dump(&dump);
    assert!(st.interface_exists);
    assert_eq!(st.peer_count, 1);
    assert!(st.latest_handshake_secs_ago.unwrap() <= 30);
    assert_eq!((st.rx_bytes, st.tx_bytes), (1234, 5678));
    let h = health_from(&st, true, true);
    assert_eq!(h, mullvad_helper_core::TunnelHealth::Connected);
}

#[test]
fn no_handshake_means_waiting() {
    let dump = "priv\tpub\t51820\toff\nPEER\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t0\t0\t0\toff\n";
    let st = parse_wg_dump(dump);
    assert_eq!(health_from(&st, true, true), mullvad_helper_core::TunnelHealth::WaitingForHandshake);
}

#[tokio::test]
async fn deps_detect_missing_wireguard() {
    let m = MockRunner::new();
    for bin in ["wg", "wg-quick"] {
        let probe = format!("command -v {bin}");
        // leak-free: build owned key then stub with leaked refs is avoided by direct stub call shape
        m.stub("sh", &["-c", Box::leak(probe.into_boxed_str())], fail(1, ""));
    }
    m.stub("sh", &["-c", "command -v resolvconf"], ok("/usr/bin/resolvconf\n"));
    m.stub("sh", &["-c", "command -v systemctl"], ok("/usr/bin/systemctl\n"));
    m.stub("sh", &["-c", "command -v nft"], fail(1, ""));
    m.stub("sh", &["-c", "command -v ip"], ok("/usr/bin/ip\n"));
    m.stub("sh", &["-c", "command -v pacman"], ok("/usr/bin/pacman\n"));
    m.stub("systemctl", &["is-active", "systemd-resolved.service"], ok("active\n"));
    let svc = DepsService::new(Arc::new(m));
    let checks = svc.check_all().await;
    assert!(!checks.iter().find(|c| c.id == "wg").unwrap().present);
    let pkgs = DepsService::<MockRunner>::missing_arch_packages(&checks);
    assert!(pkgs.contains(&"wireguard-tools".to_string()));
}
