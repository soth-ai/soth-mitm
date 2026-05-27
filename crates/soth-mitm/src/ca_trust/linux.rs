use std::path::{Path, PathBuf};

use crate::{CaError, CertificateAuthority};

use super::backend_common::{
    clear_state, operation_error, read_state, run_command, write_staged_cert, write_state,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DistroFamily {
    DebianUbuntu,
    RhelFedora,
    Arch,
    Alpine,
    Suse,
    Unknown,
}

impl DistroFamily {
    fn anchor_path(self) -> &'static str {
        match self {
            Self::DebianUbuntu | Self::Alpine | Self::Unknown => {
                "/usr/local/share/ca-certificates/soth-mitm-local-ca.crt"
            }
            Self::RhelFedora => "/etc/pki/ca-trust/source/anchors/soth-mitm-local-ca.crt",
            Self::Arch => "/etc/ca-certificates/trust-source/anchors/soth-mitm-local-ca.crt",
            Self::Suse => "/etc/pki/trust/anchors/soth-mitm-local-ca.crt",
        }
    }

    fn update_tool(self) -> &'static str {
        match self {
            Self::DebianUbuntu | Self::Alpine | Self::Suse | Self::Unknown => {
                "update-ca-certificates"
            }
            Self::RhelFedora | Self::Arch => "update-ca-trust",
        }
    }

    fn ca_bundle(self) -> &'static Path {
        match self {
            Self::RhelFedora | Self::Arch => Path::new("/etc/pki/tls/certs/ca-bundle.crt"),
            Self::Suse => Path::new("/var/lib/ca-certificates/ca-bundle.pem"),
            _ => Path::new("/etc/ssl/certs/ca-certificates.crt"),
        }
    }
}

fn detect_distro() -> DistroFamily {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let lower = os_release.to_ascii_lowercase();
    let id_line = lower
        .lines()
        .find(|line| line.starts_with("id="))
        .unwrap_or("");
    let id_like_line = lower
        .lines()
        .find(|line| line.starts_with("id_like="))
        .unwrap_or("");
    let combined = format!("{id_line} {id_like_line}");

    if combined.contains("alpine") {
        return DistroFamily::Alpine;
    }
    if combined.contains("arch") || combined.contains("manjaro") {
        return DistroFamily::Arch;
    }
    if combined.contains("suse") || combined.contains("sles") {
        return DistroFamily::Suse;
    }
    if combined.contains("rhel")
        || combined.contains("fedora")
        || combined.contains("centos")
        || combined.contains("rocky")
        || combined.contains("alma")
        || combined.contains("amzn")
    {
        return DistroFamily::RhelFedora;
    }
    if combined.contains("debian") || combined.contains("ubuntu") {
        return DistroFamily::DebianUbuntu;
    }
    DistroFamily::Unknown
}

#[derive(Debug, Default)]
pub(crate) struct PlatformTrustBackend;

impl PlatformTrustBackend {
    pub(crate) fn install(&self, ca: &CertificateAuthority) -> Result<(), CaError> {
        let cert_path = write_staged_cert("linux", &ca.cert_pem)?;

        let trust_store_path = system_ca_path();
        if let Some(parent) = trust_store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&trust_store_path, &ca.cert_pem).map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return CaError::PermissionDenied {
                    operation: "install_ca_trust".to_string(),
                    detail: error.to_string(),
                };
            }
            CaError::Io(error)
        })?;

        let update_tool = detect_distro().update_tool();
        // update-ca-certificates takes --fresh; update-ca-trust is invoked bare.
        let outcome = if update_tool == "update-ca-certificates" {
            run_command("install_ca_trust", update_tool, ["--fresh"])?
        } else {
            run_command("install_ca_trust", update_tool, std::iter::empty::<&str>())?
        };
        if !outcome.success {
            return Err(operation_error("install_ca_trust", outcome.stderr));
        }

        write_state("linux", &ca.fingerprint, &cert_path)?;
        Ok(())
    }

    pub(crate) fn uninstall(&self) -> Result<(), CaError> {
        let trust_store_path = system_ca_path();
        match std::fs::remove_file(&trust_store_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(CaError::PermissionDenied {
                    operation: "uninstall_ca_trust".to_string(),
                    detail: error.to_string(),
                });
            }
            Err(error) => return Err(CaError::Io(error)),
        }

        let update_tool = detect_distro().update_tool();
        let outcome = if update_tool == "update-ca-certificates" {
            run_command("uninstall_ca_trust", update_tool, ["--fresh"])?
        } else {
            run_command(
                "uninstall_ca_trust",
                update_tool,
                std::iter::empty::<&str>(),
            )?
        };
        if !outcome.success {
            return Err(operation_error("uninstall_ca_trust", outcome.stderr));
        }
        clear_state("linux")
    }

    pub(crate) fn is_trusted(&self, fingerprint: &str) -> Result<bool, CaError> {
        let Some((stored_fingerprint, cert_path)) = read_state("linux")? else {
            return Ok(false);
        };
        if stored_fingerprint != fingerprint {
            return Ok(false);
        }

        let ca_bundle = default_ca_bundle();
        let args = [
            "verify",
            "-CAfile",
            ca_bundle
                .to_str()
                .ok_or_else(|| operation_error("is_ca_trusted", "invalid CA bundle path"))?,
            cert_path
                .to_str()
                .ok_or_else(|| operation_error("is_ca_trusted", "invalid staged cert path"))?,
        ];
        let outcome = run_command("is_ca_trusted", "openssl", args)?;
        Ok(outcome.success)
    }
}

fn system_ca_path() -> PathBuf {
    if let Some(path) = std::env::var_os("SOTH_MITM_LINUX_CA_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(detect_distro().anchor_path())
}

fn default_ca_bundle() -> &'static Path {
    detect_distro().ca_bundle()
}
