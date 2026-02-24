use std::net::IpAddr;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};

use crate::errors::CaError;
use crate::types::TlsVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuedLeafContract {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub san_host: String,
}

pub(crate) fn issue_leaf_for_sni(sni: &str) -> Result<IssuedLeafContract, CaError> {
    let sni = sni.trim();
    if sni.is_empty() {
        return Err(CaError::InvalidMaterial(
            "client hello SNI must not be empty".to_string(),
        ));
    }

    let ca_key =
        KeyPair::generate().map_err(|error| CaError::InvalidMaterial(error.to_string()))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "soth-mitm Leaf Test CA");
    ca_params.distinguished_name = ca_dn;
    ca_params
        .self_signed(&ca_key)
        .map_err(|error| CaError::InvalidMaterial(error.to_string()))?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key =
        KeyPair::generate().map_err(|error| CaError::InvalidMaterial(error.to_string()))?;
    let mut leaf_params = CertificateParams::default();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, sni.to_string());
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    if let Ok(ip) = sni.parse::<IpAddr>() {
        leaf_params.subject_alt_names.push(SanType::IpAddress(ip));
    } else {
        leaf_params
            .subject_alt_names
            .push(SanType::DnsName(sni.try_into().map_err(|error| {
                CaError::InvalidMaterial(format!("invalid SNI DNS name: {error}"))
            })?));
    }

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .map_err(|error| CaError::InvalidMaterial(error.to_string()))?;

    Ok(IssuedLeafContract {
        cert_pem: leaf_cert.pem().into_bytes(),
        key_pem: leaf_key.serialize_pem().into_bytes(),
        san_host: sni.to_string(),
    })
}

pub(crate) fn negotiated_tls_versions(min_version: TlsVersion) -> Vec<TlsVersion> {
    match min_version {
        TlsVersion::Tls12 => vec![TlsVersion::Tls12, TlsVersion::Tls13],
        TlsVersion::Tls13 => vec![TlsVersion::Tls13],
    }
}

#[cfg(test)]
mod tests {
    use crate::types::TlsVersion;

    use super::{issue_leaf_for_sni, negotiated_tls_versions};

    #[test]
    fn leaf_cert_san_matches_clienthello_sni() {
        let issued = issue_leaf_for_sni("api.example.com").expect("leaf cert should issue");
        assert_eq!(issued.san_host, "api.example.com");
        assert!(!issued.cert_pem.is_empty());
        assert!(!issued.key_pem.is_empty());
    }

    #[test]
    fn tls12_tls13_negotiation_matrix() {
        let tls12_matrix = negotiated_tls_versions(TlsVersion::Tls12);
        assert_eq!(tls12_matrix, vec![TlsVersion::Tls12, TlsVersion::Tls13]);

        let tls13_matrix = negotiated_tls_versions(TlsVersion::Tls13);
        assert_eq!(tls13_matrix, vec![TlsVersion::Tls13]);
    }
}
