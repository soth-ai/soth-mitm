use std::path::PathBuf;

use crate::{CaError, CertificateAuthority};

use super::backend_common::{
    clear_state, operation_error, read_state, run_command, write_staged_cert, write_state,
};

#[derive(Debug, Default)]
pub(crate) struct PlatformTrustBackend;

impl PlatformTrustBackend {
    pub(crate) fn install(&self, ca: &CertificateAuthority) -> Result<(), CaError> {
        let cert_path = write_staged_cert("macos", &ca.cert_pem)?;
        let keychain = login_keychain_path()?;

        if self.is_trusted(&ca.fingerprint)? {
            write_state("macos", &ca.fingerprint, &cert_path)?;
            return Ok(());
        }

        let args = [
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            keychain
                .to_str()
                .ok_or_else(|| operation_error("install_ca_trust", "invalid keychain path"))?,
            cert_path
                .to_str()
                .ok_or_else(|| operation_error("install_ca_trust", "invalid cert path"))?,
        ];
        let outcome = run_command("install_ca_trust", "security", args)?;
        if !outcome.success {
            return Err(operation_error("install_ca_trust", outcome.stderr));
        }

        write_state("macos", &ca.fingerprint, &cert_path)?;
        Ok(())
    }

    pub(crate) fn uninstall(&self) -> Result<(), CaError> {
        let Some((_, cert_path)) = read_state("macos")? else {
            return Ok(());
        };
        let outcome = run_command(
            "uninstall_ca_trust",
            "security",
            [
                "remove-trusted-cert",
                "-d",
                cert_path.to_str().ok_or_else(|| {
                    operation_error("uninstall_ca_trust", "invalid staged cert path")
                })?,
            ],
        )?;
        if !outcome.success {
            let lower = outcome.stderr.to_ascii_lowercase();
            if !lower.contains("could not find") && !lower.contains("not found") {
                return Err(operation_error("uninstall_ca_trust", outcome.stderr));
            }
        }
        clear_state("macos")
    }

    pub(crate) fn is_trusted(&self, fingerprint: &str) -> Result<bool, CaError> {
        let Some((stored_fingerprint, cert_path)) = read_state("macos")? else {
            return Ok(false);
        };
        if stored_fingerprint != fingerprint {
            return Ok(false);
        }

        let keychain = login_keychain_path()?;
        let outcome = run_command(
            "is_ca_trusted",
            "security",
            [
                "verify-cert",
                "-c",
                cert_path
                    .to_str()
                    .ok_or_else(|| operation_error("is_ca_trusted", "invalid staged cert path"))?,
                "-k",
                keychain
                    .to_str()
                    .ok_or_else(|| operation_error("is_ca_trusted", "invalid keychain path"))?,
            ],
        )?;
        Ok(outcome.success)
    }
}

fn login_keychain_path() -> Result<PathBuf, CaError> {
    let Some(home) = std::env::var_os("HOME") else {
        return Err(CaError::UnsupportedOperation(
            "HOME is not set; cannot resolve macOS login keychain".to_string(),
        ));
    };
    Ok(PathBuf::from(home).join("Library/Keychains/login.keychain-db"))
}
