use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

use crate::ca_trust;
use crate::{CaError, MitmError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthority {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub fingerprint: String,
}

pub fn generate_ca() -> Result<CertificateAuthority, CaError> {
    let key = KeyPair::generate().map_err(|error| CaError::InvalidMaterial(error.to_string()))?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "soth-mitm Local CA");
    dn.push(DnType::OrganizationName, "soth-mitm");
    params.distinguished_name = dn;

    let cert = params
        .self_signed(&key)
        .map_err(|error| CaError::InvalidMaterial(error.to_string()))?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key.serialize_pem().into_bytes();

    Ok(CertificateAuthority {
        fingerprint: fingerprint_from_pem(&cert_pem),
        cert_pem,
        key_pem,
    })
}

pub fn load_ca(cert: &[u8], key: &[u8]) -> Result<CertificateAuthority, CaError> {
    if cert.is_empty() {
        return Err(CaError::InvalidMaterial(
            "certificate PEM must not be empty".to_string(),
        ));
    }
    if key.is_empty() {
        return Err(CaError::InvalidMaterial(
            "private key PEM must not be empty".to_string(),
        ));
    }

    Ok(CertificateAuthority {
        cert_pem: cert.to_vec(),
        key_pem: key.to_vec(),
        fingerprint: fingerprint_from_pem(cert),
    })
}

pub fn load_ca_from_files(
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> Result<CertificateAuthority, CaError> {
    let cert = std::fs::read(cert_path.as_ref()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return CaError::PermissionDenied {
                operation: "read_ca_cert".to_string(),
                detail: error.to_string(),
            };
        }
        CaError::Io(error)
    })?;

    let key = std::fs::read(key_path.as_ref()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return CaError::PermissionDenied {
                operation: "read_ca_key".to_string(),
                detail: error.to_string(),
            };
        }
        CaError::Io(error)
    })?;

    load_ca(&cert, &key)
}

pub fn install_ca_system_trust(_ca: &CertificateAuthority) -> Result<(), CaError> {
    ca_trust::install(_ca)
}

pub fn uninstall_ca_system_trust() -> Result<(), CaError> {
    ca_trust::uninstall()
}

pub fn is_ca_trusted(_fingerprint: &str) -> Result<bool, CaError> {
    ca_trust::is_trusted(_fingerprint)
}

#[allow(dead_code)]
pub(crate) fn map_ca_error_to_mitm_error(error: CaError) -> MitmError {
    match error {
        CaError::PermissionDenied { operation, detail } => {
            MitmError::CaLoadFailed(format!("permission denied for {operation}: {detail}"))
        }
        CaError::OperationFailed(detail) => MitmError::CaOperationFailed(detail),
        CaError::InvalidMaterial(detail) => MitmError::CaLoadFailed(detail),
        CaError::UnsupportedOperation(detail) => MitmError::CaOperationFailed(detail),
        CaError::Io(error) => MitmError::CaLoadFailed(error.to_string()),
    }
}

#[allow(dead_code)]
pub(crate) fn load_ca_for_startup(
    cert: &[u8],
    key: &[u8],
) -> Result<CertificateAuthority, MitmError> {
    load_ca(cert, key).map_err(map_ca_error_to_mitm_error)
}

fn fingerprint_from_pem(cert: &[u8]) -> String {
    let mut rendered = String::with_capacity(2 * cert.len().min(16) + 4);
    for byte in cert.iter().take(16) {
        rendered.push(hex_digit(byte >> 4));
        rendered.push(hex_digit(byte & 0x0f));
    }
    rendered.push(':');
    rendered.push_str(&cert.len().to_string());
    rendered
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_ca, load_ca, load_ca_for_startup, map_ca_error_to_mitm_error};
    use crate::{CaError, MitmError};

    #[test]
    fn ca_generate_load_api_contract() {
        let generated = generate_ca().expect("generate ca");
        let loaded = load_ca(&generated.cert_pem, &generated.key_pem).expect("load generated ca");
        assert!(!loaded.fingerprint.is_empty());
        assert_eq!(loaded.cert_pem, generated.cert_pem);
        assert_eq!(loaded.key_pem, generated.key_pem);
    }

    #[test]
    fn ca_permission_denied_error_mapping() {
        let mapped = map_ca_error_to_mitm_error(CaError::PermissionDenied {
            operation: "read_ca_cert".to_string(),
            detail: "os error 13".to_string(),
        });
        match mapped {
            MitmError::CaLoadFailed(detail) => {
                assert!(detail.contains("permission denied"));
                assert!(detail.contains("read_ca_cert"));
            }
            other => panic!("unexpected mapped error: {other}"),
        }
    }

    #[test]
    fn startup_fails_with_ca_load_failed_when_ca_invalid() {
        let error = load_ca_for_startup(b"", b"key").expect_err("invalid ca should fail");
        match error {
            MitmError::CaLoadFailed(detail) => {
                assert!(detail.contains("certificate PEM must not be empty"));
            }
            other => panic!("unexpected startup error: {other}"),
        }
    }
}
