use crate::{CaError, CertificateAuthority};

use super::backend_common::{
    clear_state, operation_error, read_state, run_command, write_staged_cert, write_state,
};

#[derive(Debug, Default)]
pub(crate) struct PlatformTrustBackend;

impl PlatformTrustBackend {
    pub(crate) fn install(&self, ca: &CertificateAuthority) -> Result<(), CaError> {
        let cert_path = write_staged_cert("windows", &ca.cert_pem)?;
        let cert_arg = cert_path
            .to_str()
            .ok_or_else(|| operation_error("install_ca_trust", "invalid staged cert path"))?;
        let outcome = run_command(
            "install_ca_trust",
            "certutil",
            ["-f", "-addstore", "Root", cert_arg],
        )?;
        if !outcome.success {
            return Err(operation_error("install_ca_trust", outcome.stderr));
        }

        write_state("windows", &ca.fingerprint, &cert_path)?;
        Ok(())
    }

    pub(crate) fn uninstall(&self) -> Result<(), CaError> {
        let Some((fingerprint, _)) = read_state("windows")? else {
            return Ok(());
        };

        let outcome = run_command(
            "uninstall_ca_trust",
            "certutil",
            ["-delstore", "Root", &fingerprint],
        )?;
        if !outcome.success {
            let lower = outcome.stderr.to_ascii_lowercase();
            if !lower.contains("cannot find") && !lower.contains("not found") {
                return Err(operation_error("uninstall_ca_trust", outcome.stderr));
            }
        }
        clear_state("windows")
    }

    pub(crate) fn is_trusted(&self, fingerprint: &str) -> Result<bool, CaError> {
        let Some((stored_fingerprint, _)) = read_state("windows")? else {
            return Ok(false);
        };
        if stored_fingerprint != fingerprint {
            return Ok(false);
        }
        let outcome = run_command("is_ca_trusted", "certutil", ["-store", "Root", fingerprint])?;
        Ok(outcome.success)
    }
}
