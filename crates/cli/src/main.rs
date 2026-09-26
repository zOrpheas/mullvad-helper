//! mullvad-helper CLI: status/connect/disconnect/list/doctor/import.
use clap::{Parser, Subcommand};
use std::sync::Arc;
use mullvad_helper_backend::command::SystemRunner;

#[derive(Parser)]
#[command(name = "mullvad-helper", version, about = "Mullvad Helper — WireGuard made simple")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long, global = true, default_value = "")]
    ip_endpoint: String,
}

#[derive(Subcommand)]
enum Cmd {
    Status,
    Connect { name: String },
    Disconnect { name: String },
    List,
    Doctor,
    Import { path: String, #[arg(long)] name: Option<String> },
}

fn services() -> (Arc<SystemRunner>, Arc<mullvad_helper_backend::privilege::PrivilegeService<SystemRunner>>) {
    let r = Arc::new(SystemRunner);
    let p = Arc::new(mullvad_helper_backend::privilege::PrivilegeService::new(r.clone()));
    (r, p)
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mullvad_helper_core::logging::init_logging();
    let cli = Cli::parse();
    let (runner, privs) = services();
    match cli.cmd {
        Cmd::Status => cmd_status(runner, &cli.ip_endpoint).await?,
        Cmd::Connect { name } => {
            let wg = mullvad_helper_backend::wireguard::WireGuardService::new(runner, privs);
            match wg.connect(&name).await {
                Ok(_) => println!("Connected {name}"),
                Err(e) => {
                    println!("Could not connect: {}", e.human());
                    println!("Technical: {}", mullvad_helper_core::redact::redact_secrets(&e.technical()));
                    std::process::exit(1);
                }
            }
        }
        Cmd::Disconnect { name } => {
            let wg = mullvad_helper_backend::wireguard::WireGuardService::new(runner, privs);
            match wg.disconnect(&name).await {
                Ok(_) => println!("Disconnected {name}"),
                Err(e) => {
                    println!("Could not disconnect: {}", e.human());
                    std::process::exit(1);
                }
            }
        }
        Cmd::List => {
            let store = mullvad_helper_backend::configs::ConfigStore::new(runner, privs);
            for c in store.list().await {
                println!("{} {} ({}) autostart={}", if c.active { "●" } else { "○" },
                    c.metadata.display_name, c.metadata.name,
                    if c.autostart_enabled { "on" } else { "off" });
            }
        }
        Cmd::Doctor => cmd_doctor(runner, privs).await?,
        Cmd::Import { path, name } => cmd_import(runner, privs, &path, name).await?,
    }
    Ok(())
}


async fn cmd_status(runner: Arc<SystemRunner>, ip_endpoint: &str) -> anyhow::Result<()> {
    let privs = Arc::new(mullvad_helper_backend::privilege::PrivilegeService::new(runner.clone()));
    let wg = mullvad_helper_backend::wireguard::WireGuardService::new(runner.clone(), privs);
    let dns = mullvad_helper_backend::dns::DnsService::new(runner.clone());
    let active = wg.active_interfaces().await;
    println!("Mullvad Helper status");
    let label = if active.is_empty() { "(none)".to_string() } else { active.join(", ") };
    println!("Active interfaces: {label}");
    for iface in &active {
        if let Ok(st) = wg.status(iface).await {
            let hs = st.latest_handshake_secs_ago.map(|s| format!("{s}s ago")).unwrap_or("never".into());
            println!("  {iface}: peers={} handshake={hs} rx={} tx={}", st.peer_count, st.rx_bytes, st.tx_bytes);
        }
    }
    let info = dns.detect().await;
    println!("DNS: {} ({})", info.architecture.human_label(), info.summary);
    if let Some(p) = info.problem {
        println!("DNS problem: {p}");
    }
    match mullvad_helper_backend::netcheck::public_ip(ip_endpoint).await {
        Ok(ip) => println!("Public IP: {}", ip.ip),
        Err(e) => println!("Public IP: unavailable ({e:#})"),
    }
    Ok(())
}

async fn cmd_doctor(runner: Arc<SystemRunner>, privs: Arc<mullvad_helper_backend::privilege::PrivilegeService<SystemRunner>>) -> anyhow::Result<()> {
    let wg = mullvad_helper_backend::wireguard::WireGuardService::new(runner.clone(), privs.clone());
    let active = wg.active_interfaces().await;
    let doc = mullvad_helper_backend::doctor::Doctor::new(runner.clone(), privs.clone());
    println!("Mullvad Helper Doctor\n");
    for c in doc.run(active.first().map(|s| s.as_str())).await {
        println!("{} {} — {}", if c.ok { "✓" } else { "✗" }, c.label, c.message);
    }
    println!();
    for d in mullvad_helper_backend::deps::DepsService::new(runner).check_all().await {
        println!("{} {} — {}", if d.present { "✓" } else { "✗" }, d.label, d.detail);
    }
    Ok(())
}

async fn cmd_import(runner: Arc<SystemRunner>, privs: Arc<mullvad_helper_backend::privilege::PrivilegeService<SystemRunner>>, path: &str, name: Option<String>) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let file_name = name.unwrap_or_else(|| {
        std::path::Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or("tunnel.conf").to_string()
    });
    let store = mullvad_helper_backend::configs::ConfigStore::new(runner.clone(), privs.clone());
    let meta = match store.validate_import(&file_name, &raw) {
        Ok(m) => m,
        Err(e) => {
            println!("Invalid WireGuard config: {e}");
            std::process::exit(1);
        }
    };
    if meta.hooks_look_risky {
        println!("WARNING: this config wants to run shell commands as root:");
        for h in &meta.hook_commands {
            println!("  {h}");
        }
    }
    let staging = format!("/tmp/mullvad-helper-{}.conf", meta.name);
    std::fs::write(&staging, &raw)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600))?;
    }
    match store.install_staged(&staging, &meta.name).await {
        Ok(_) => {
            let _ = std::fs::remove_file(&staging);
            store.remember(&meta);
            println!("Installed /etc/wireguard/{}.conf (mode 0600).", meta.name);
            println!("Endpoint: {}:{}", meta.endpoint_host, meta.endpoint_port);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&staging);
            println!("Install failed: {e:#}");
            std::process::exit(1);
        }
    }
    Ok(())
}
