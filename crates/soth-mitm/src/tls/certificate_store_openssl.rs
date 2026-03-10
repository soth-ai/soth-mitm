#[cfg(feature = "openssl-backend")]
fn validate_ca_material_with_openssl(
    ca_cert_path: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), TlsConfigError> {
    use openssl::pkey::PKey;
    use openssl::x509::X509;

    let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse CA certificate with openssl from {ca_cert_path}: {error}"
        ))
    })?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse CA private key with openssl from {ca_cert_path}: {error}"
        ))
    })?;
    let public = cert.public_key().map_err(|error| {
        TlsConfigError::InvalidConfiguration(format!(
            "failed to parse CA public key with openssl from {ca_cert_path}: {error}"
        ))
    })?;
    if !public.public_eq(&key) {
        return Err(TlsConfigError::InvalidConfiguration(format!(
            "CA certificate and key mismatch detected by openssl for {ca_cert_path}"
        )));
    }
    Ok(())
}

#[cfg(not(feature = "openssl-backend"))]
fn validate_ca_material_with_openssl(
    _ca_cert_path: &str,
    _cert_pem: &str,
    _key_pem: &str,
) -> Result<(), TlsConfigError> {
    Ok(())
}
