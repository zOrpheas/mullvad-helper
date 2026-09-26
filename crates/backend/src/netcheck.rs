//! Public-IP + connectivity checks. No keys/configs ever transmitted.
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MullvadCheck {
    ip: Option<String>,
    mullvad_exit_ip: Option<bool>,
    country: Option<String>,
    city: Option<String>,
}

/// Connectivity: can we reach the internet at all (captive-portal style).
pub async fn internet_ok() -> bool {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(6)).build();
    let Ok(client) = client else { return false };
    // Lightweight, no payload sent.
    client.get("https://connectivity-check.ubuntu.com").send().await.map(|r| r.status().is_success()).unwrap_or(false)
}

/// Public IP via configurable endpoint. Defaults to Mullvad check.
pub async fn public_ip(endpoint: &str) -> Result<mullvad_helper_core::PublicIpInfo, anyhow::Error> {
    let url = if endpoint.trim().is_empty() {
        "https://am.i.mullvad.net/json".to_string()
    } else {
        endpoint.trim().to_string()
    };
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(8)).build()?;
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("IP check failed: HTTP {status}");
    }
    if url.contains("mullvad") {
        let j: MullvadCheck = resp.json().await?;
        let ip = j.ip.unwrap_or_default();
        if ip.is_empty() {
            anyhow::bail!("IP check returned no address");
        }
        return Ok(mullvad_helper_core::PublicIpInfo {
            ip, mullvad_exit: j.mullvad_exit_ip, country: j.country, city: j.city, endpoint_used: url,
        });
    }
    // Generic endpoint: try JSON {ip:..} then raw text.
    let text = resp.text().await?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(ip) = v.get("ip").and_then(|x| x.as_str()) {
            return Ok(mullvad_helper_core::PublicIpInfo {
                ip: ip.trim().to_string(), mullvad_exit: None,
                country: v.get("country").and_then(|x| x.as_str()).map(|s| s.to_string()),
                city: v.get("city").and_then(|x| x.as_str()).map(|s| s.to_string()),
                endpoint_used: url,
            });
        }
    }
    let ip = text.trim().to_string();
    if ip.is_empty() {
        anyhow::bail!("IP check returned no address");
    }
    Ok(mullvad_helper_core::PublicIpInfo { ip, mullvad_exit: None, country: None, city: None, endpoint_used: url })
}
