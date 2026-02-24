use std::path::{Path, PathBuf};

use crate::{CaError, CertificateAuthority};

use super::backend_common::{
    clear_state, operation_error, read_state, run_command, write_staged_cert, write_state,
};

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

        let outcome = run_command("install_ca_trust", "update-ca-certificates", ["--fresh"])?;
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

        let outcome = run_command("uninstall_ca_trust", "update-ca-certificates", ["--fresh"])?;
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
    PathBuf::from("/usr/local/share/ca-certificates/soth-mitm-local-ca.crt")
}

fn default_ca_bundle() -> &'static Path {
    Path::new("/etc/ssl/certs/ca-certificates.crt")
}
