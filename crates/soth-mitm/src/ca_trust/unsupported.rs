use crate::{CaError, CertificateAuthority};

#[derive(Debug, Default)]
pub(crate) struct PlatformTrustBackend;

impl PlatformTrustBackend {
    pub(crate) fn install(&self, _ca: &CertificateAuthority) -> Result<(), CaError> {
        Err(CaError::UnsupportedOperation(
            "system trust install unsupported on this platform".to_string(),
        ))
    }

    pub(crate) fn uninstall(&self) -> Result<(), CaError> {
        Err(CaError::UnsupportedOperation(
            "system trust uninstall unsupported on this platform".to_string(),
        ))
    }

    pub(crate) fn is_trusted(&self, _fingerprint: &str) -> Result<bool, CaError> {
        Err(CaError::UnsupportedOperation(
            "system trust query unsupported on this platform".to_string(),
        ))
    }
}
