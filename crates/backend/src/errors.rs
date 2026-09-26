//! Human-friendly error mapping. Raw stderr always kept in `technical`.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("{human}")]
    Friendly {
        human: String,
        technical: String,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl TunnelError {
    pub fn friendly(human: impl Into<String>, technical: impl Into<String>) -> Self {
        Self::Friendly {
            human: human.into(),
            technical: technical.into(),
        }
    }
    pub fn human(&self) -> String {
        match self {
            Self::Friendly { human, .. } => human.clone(),
            Self::Other(e) => format!("{e:#}"),
        }
    }
    pub fn technical(&self) -> String {
        match self {
            Self::Friendly { technical, .. } => technical.clone(),
            Self::Other(e) => format!("{e:?}"),
        }
    }
}

/// Map wg-quick stderr to plain-language explanations.
pub fn explain_wg_quick_error(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("permission denied") {
        return "WireGuard could not access the configuration. The app will repair the configuration permissions.".into();
    }
    if lower.contains("already exists") || lower.contains("device or resource busy") {
        return "The VPN interface is already running.".into();
    }
    if lower.contains("resolvconf") {
        return "Your DNS resolver configuration is managed by systemd-resolved, but the installed resolvconf implementation is incompatible.".into();
    }
    if lower.contains("command not found") || lower.contains("no such file") {
        return "A required WireGuard tool is missing. Install the WireGuard tools first.".into();
    }
    "The tunnel could not be started. See Technical details for the exact system message.".into()
}
