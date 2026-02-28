use crate::types::{TlsClientFingerprint, TlsVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawTlsFingerprint<'a> {
    pub ja3: &'a str,
    pub ja4: &'a str,
    pub tls_version: TlsVersion,
    pub cipher_suites: &'a [u16],
    pub extensions: &'a [u16],
    pub elliptic_curves: &'a [u16],
}

pub(crate) fn maybe_capture_fingerprint(
    enabled: bool,
    raw: Option<RawTlsFingerprint<'_>>,
) -> Option<TlsClientFingerprint> {
    if !enabled {
        return None;
    }
    let raw = raw?;
    Some(TlsClientFingerprint {
        ja4: raw.ja4.to_string(),
        ja3: raw.ja3.to_string(),
        tls_version: raw.tls_version,
        cipher_suites: raw.cipher_suites.to_vec(),
        extensions: raw.extensions.to_vec(),
        elliptic_curves: raw.elliptic_curves.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use crate::types::TlsVersion;

    use super::{maybe_capture_fingerprint, RawTlsFingerprint};

    #[test]
    fn fingerprint_populated_when_enabled() {
        let captured = maybe_capture_fingerprint(
            true,
            Some(RawTlsFingerprint {
                ja3: "771,4865-4866-4867,0-11-10,29-23-24,0",
                ja4: "t13d1516h2_8daaf6152771_02713d6af862",
                tls_version: TlsVersion::Tls13,
                cipher_suites: &[4865, 4866, 4867],
                extensions: &[0, 11, 10],
                elliptic_curves: &[29, 23, 24],
            }),
        );

        let fingerprint = captured.expect("fingerprint should be captured");
        assert_eq!(fingerprint.ja4, "t13d1516h2_8daaf6152771_02713d6af862");
        assert_eq!(fingerprint.ja3, "771,4865-4866-4867,0-11-10,29-23-24,0");
        assert_eq!(fingerprint.tls_version, TlsVersion::Tls13);
        assert_eq!(fingerprint.cipher_suites, vec![4865, 4866, 4867]);
    }

    #[test]
    fn fingerprint_none_when_disabled() {
        let captured = maybe_capture_fingerprint(
            false,
            Some(RawTlsFingerprint {
                ja3: "value",
                ja4: "value",
                tls_version: TlsVersion::Tls12,
                cipher_suites: &[4865],
                extensions: &[0],
                elliptic_curves: &[29],
            }),
        );
        assert!(captured.is_none());
    }

    #[test]
    fn fingerprint_capture_contract_round_trip() {
        let captured = maybe_capture_fingerprint(
            true,
            Some(RawTlsFingerprint {
                ja3: "771,4865-4866,0-11,29-23,0",
                ja4: "t13d1516h2_test",
                tls_version: TlsVersion::Tls13,
                cipher_suites: &[4865, 4866],
                extensions: &[0, 11],
                elliptic_curves: &[29, 23],
            }),
        );
        let fingerprint = captured.expect("fingerprint should be captured");
        assert_eq!(fingerprint.ja4, "t13d1516h2_test");
        assert_eq!(fingerprint.ja3, "771,4865-4866,0-11,29-23,0");
        assert_eq!(fingerprint.tls_version, TlsVersion::Tls13);
    }
}
