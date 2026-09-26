// Refresh snapshot from backends.
use crate::state::{ConfigRow, health_of};
use crate::worker::Worker;

pub(crate) async fn refresh_inner(w: &mut Worker, full: bool) {
    let wg = mullvad_helper_backend::wireguard::WireGuardService::new(
        w.be.runner.clone(),
        w.be.privs.clone(),
    );
    let dns = mullvad_helper_backend::dns::DnsService::new(w.be.runner.clone());
    let store = mullvad_helper_backend::configs::ConfigStore::new(
        w.be.runner.clone(),
        w.be.privs.clone(),
    );
    let active = wg.active_interfaces().await;
    let first = active.first().cloned();
    let status = match &first {
        Some(i) => wg.status(i).await.ok(),
        None => None,
    };
    let info = dns.detect().await;
    let list = store.list().await;
    w.snap.active_iface = first.clone();
    w.snap.status = status.clone();
    w.snap.dns = Some(info.clone());
    w.snap.dns_fix = mullvad_helper_backend::dns::DnsService::<
        crate::state::Runner,
    >::suggested_resolvconf_fix(&info);
    w.snap.health = health_of(
        status.as_ref(),
        w.snap.internet_ok,
        w.snap.ip.is_some(),
    );
    let sysd = mullvad_helper_backend::systemd::SystemdService::new(
        w.be.runner.clone(),
        w.be.privs.clone(),
    );
    let mut rows = Vec::new();
    for c in &list {
        rows.push(ConfigRow {
            name: c.metadata.name.clone(),
            display: c.metadata.display_name.clone(),
            active: c.active,
            autostart: sysd.is_enabled(&c.metadata.name).await,
        });
    }
    for i in &active {
        if !rows.iter().any(|r| &r.name == i) {
            rows.push(ConfigRow {
                name: i.clone(),
                display: format!("{i} (manual)"),
                active: true,
                autostart: sysd.is_enabled(i).await,
            });
        }
    }
    rows.sort_by(|a, b| b.active.cmp(&a.active).then(a.name.cmp(&b.name)));
    w.snap.configs = rows;
    if w.snap.selected.is_none() {
        w.snap.selected = first.clone().or_else(|| {
            w.snap
                .configs
                .iter()
                .find(|c| !c.active)
                .map(|c| c.name.clone())
        });
    }
    if full {
        let deps = mullvad_helper_backend::deps::DepsService::new(w.be.runner.clone());
        let checks = deps.check_all().await;
        w.snap.missing_packages = mullvad_helper_backend::deps::DepsService::<
            crate::state::Runner,
        >::missing_arch_packages(&checks);
        w.snap.deps = checks;
        if w.want_doctor {
            let doc = mullvad_helper_backend::doctor::Doctor::new(w.be.runner.clone(), w.be.privs.clone());
            w.snap.doctor = doc.run(w.snap.active_iface.as_deref()).await;
        }
    }
    w.emit();
}
