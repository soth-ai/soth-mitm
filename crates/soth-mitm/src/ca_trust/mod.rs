use std::sync::OnceLock;

use crate::{CaError, CertificateAuthority};

mod backend_common;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux::PlatformTrustBackend;
#[cfg(target_os = "macos")]
use macos::PlatformTrustBackend;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported::PlatformTrustBackend;
#[cfg(target_os = "windows")]
use windows::PlatformTrustBackend;

static TRUST_BACKEND: OnceLock<PlatformTrustBackend> = OnceLock::new();

fn backend() -> &'static PlatformTrustBackend {
    TRUST_BACKEND.get_or_init(PlatformTrustBackend::default)
}

pub(crate) fn install(ca: &CertificateAuthority) -> Result<(), CaError> {
    backend().install(ca)
}

pub(crate) fn uninstall() -> Result<(), CaError> {
    backend().uninstall()
}

pub(crate) fn is_trusted(fingerprint: &str) -> Result<bool, CaError> {
    backend().is_trusted(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::backend_common::InMemoryTrustBackend;
    use crate::generate_ca;

    #[test]
    fn ca_install_uninstall_idempotent() {
        let backend = InMemoryTrustBackend::default();
        let ca = generate_ca().expect("generate ca");

        backend.install(&ca).expect("first install");
        backend
            .install(&ca)
            .expect("second install should be idempotent");
        assert!(
            backend
                .is_trusted(&ca.fingerprint)
                .expect("lookup trusted state"),
            "ca must be trusted after idempotent install"
        );

        backend.uninstall().expect("first uninstall");
        backend
            .uninstall()
            .expect("second uninstall should be idempotent");
        assert!(
            !backend
                .is_trusted(&ca.fingerprint)
                .expect("lookup trusted state"),
            "ca must not be trusted after idempotent uninstall"
        );
    }
}
