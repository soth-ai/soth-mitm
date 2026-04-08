//! Parse TLS ClientHello from raw bytes and compute JA4 fingerprint hash.
//!
//! Called on peeked TCP bytes **before** the TLS acceptor consumes them.
//! Gracefully returns `None` on any parse failure — never blocks the
//! connection.

use crate::types::{TlsClientFingerprint, TlsVersion};
use sha2::{Digest, Sha256};

/// Parsed fields from a TLS ClientHello message.
#[derive(Debug, Clone)]
pub(crate) struct ClientHelloFields {
    pub tls_version: TlsVersion,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub supported_groups: Vec<u16>,
    pub alpn_protocols: Vec<String>,
}

// ── GREASE values (RFC 8701) — stripped from JA4 computation ─────────────────

fn is_grease(val: u16) -> bool {
    // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa
    (val & 0x0f0f) == 0x0a0a
}

// ── JA4 computation ──────────────────────────────────────────────────────────

fn truncated_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest[..6]) // first 12 hex chars = 6 bytes
}

fn ja4_version_str(v: TlsVersion) -> &'static str {
    match v {
        TlsVersion::Tls13 => "13",
        TlsVersion::Tls12 => "12",
    }
}

/// Compute the JA4 fingerprint from parsed ClientHello fields.
///
/// Format: `{q}{version}{sni}{d}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}`
///   - q = 't' (TCP)
///   - version = "13" / "12"
///   - sni = 'd' (domain present) / 'i' (IP or absent)
///   - d = 'h2' if ALPN contains h2, '00' if no ALPN, first two chars of first ALPN otherwise
///   - cipher_count = 2-digit count (capped at 99)
///   - ext_count = 2-digit count (capped at 99)
///   - cipher_hash = first 12 hex of SHA256(sorted ciphers, comma-separated)
///   - ext_hash = first 12 hex of SHA256(sorted extensions, comma-separated)
pub(crate) fn compute_ja4(fields: &ClientHelloFields) -> String {
    let q = 't'; // TCP transport
    let version = ja4_version_str(fields.tls_version);
    let sni_flag = if fields.sni.is_some() { 'd' } else { 'i' };

    // ALPN indicator: "h2" if h2 negotiated, first 2 chars of first protocol, or "00"
    let alpn_indicator = if fields.alpn_protocols.is_empty() {
        "00".to_string()
    } else if fields.alpn_protocols.iter().any(|p| p == "h2") {
        "h2".to_string()
    } else {
        let first = &fields.alpn_protocols[0];
        if first.len() >= 2 {
            first[..2].to_string()
        } else {
            format!("{first}0")
        }
    };

    // Filter GREASE values
    let mut ciphers: Vec<u16> = fields
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let mut exts: Vec<u16> = fields
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        // SNI(0) and ALPN(16) excluded from extension hash per JA4 spec
        .filter(|e| *e != 0 && *e != 16)
        .collect();

    ciphers.sort_unstable();
    exts.sort_unstable();

    let cipher_count = ciphers.len().min(99);
    let ext_count = exts.len().min(99);

    let cipher_str: String = ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_str: String = exts
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let cipher_hash = truncated_sha256(&cipher_str);
    let ext_hash = truncated_sha256(&ext_str);

    format!(
        "{q}{version}{sni_flag}{alpn_indicator}{cipher_count:02}{ext_count:02}_{cipher_hash}_{ext_hash}"
    )
}

/// Build a `TlsClientFingerprint` from parsed fields.
pub(crate) fn build_fingerprint(fields: &ClientHelloFields) -> TlsClientFingerprint {
    let ja4 = compute_ja4(fields);
    // Build a minimal JA3 string: version,ciphers,extensions,curves,point_formats
    let ciphers_str: String = fields
        .cipher_suites
        .iter()
        .filter(|c| !is_grease(**c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let exts_str: String = fields
        .extensions
        .iter()
        .filter(|e| !is_grease(**e))
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let curves_str: String = fields
        .supported_groups
        .iter()
        .filter(|g| !is_grease(**g))
        .map(|g| g.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let version_num: u16 = match fields.tls_version {
        TlsVersion::Tls13 => 771, // 0x0303
        TlsVersion::Tls12 => 771,
    };
    let ja3 = format!("{version_num},{ciphers_str},{exts_str},{curves_str},");

    TlsClientFingerprint {
        ja4,
        ja3,
        tls_version: fields.tls_version,
        cipher_suites: fields
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect(),
        extensions: fields
            .extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect(),
        elliptic_curves: fields
            .supported_groups
            .iter()
            .copied()
            .filter(|g| !is_grease(*g))
            .collect(),
    }
}

// ── TLS Record + ClientHello byte parser ─────────────────────────────────────

/// Parse peeked TCP bytes and return a fingerprint if a valid ClientHello is found.
pub(crate) fn parse_and_fingerprint(buf: &[u8]) -> Option<TlsClientFingerprint> {
    let fields = parse_client_hello(buf)?;
    Some(build_fingerprint(&fields))
}

/// Parse raw bytes as a TLS ClientHello record.
fn parse_client_hello(buf: &[u8]) -> Option<ClientHelloFields> {
    if buf.len() < 5 {
        return None;
    }

    // TLS Record header: content_type(1) + version(2) + length(2)
    let content_type = buf[0];
    if content_type != 22 {
        // Not a Handshake record
        return None;
    }

    let record_length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_length;
    if buf.len() < record_end.min(buf.len()) {
        // May be a partial peek — try to parse what we have
    }

    let handshake = &buf[5..buf.len().min(record_end)];
    if handshake.is_empty() {
        return None;
    }

    // Handshake header: msg_type(1) + length(3)
    let msg_type = handshake[0];
    if msg_type != 1 {
        // Not ClientHello
        return None;
    }
    if handshake.len() < 4 {
        return None;
    }

    let _hs_length =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);

    let body = &handshake[4..];
    parse_client_hello_body(body)
}

fn parse_client_hello_body(buf: &[u8]) -> Option<ClientHelloFields> {
    let mut pos = 0;

    // client_version(2)
    if buf.len() < pos + 2 {
        return None;
    }
    let client_version = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    // random(32)
    if buf.len() < pos + 32 {
        return None;
    }
    pos += 32;

    // session_id: length(1) + data
    if buf.len() < pos + 1 {
        return None;
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos > buf.len() {
        return None;
    }

    // cipher_suites: length(2) + data
    if buf.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if buf.len() < pos + cs_len {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    let cs_end = pos + cs_len;
    while pos + 1 < cs_end {
        cipher_suites.push(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;
    }
    pos = cs_end;

    // compression_methods: length(1) + data
    if buf.len() < pos + 1 {
        return None;
    }
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos > buf.len() {
        return None;
    }

    // Extensions: length(2) + extension data
    let mut extensions = Vec::new();
    let mut sni: Option<String> = None;
    let mut supported_groups = Vec::new();
    let mut alpn_protocols = Vec::new();
    let mut has_supported_versions = false;
    let mut max_supported_version: u16 = 0;

    if buf.len() > pos + 2 {
        let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total_len).min(buf.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            extensions.push(ext_type);

            let ext_data_end = (pos + ext_len).min(ext_end);

            match ext_type {
                0 => {
                    // SNI extension
                    sni = parse_sni_extension(&buf[pos..ext_data_end]);
                }
                10 => {
                    // supported_groups
                    supported_groups = parse_u16_list(&buf[pos..ext_data_end]);
                }
                16 => {
                    // ALPN
                    alpn_protocols = parse_alpn_extension(&buf[pos..ext_data_end]);
                }
                43 => {
                    // supported_versions
                    has_supported_versions = true;
                    if let Some(max_ver) = parse_supported_versions(&buf[pos..ext_data_end]) {
                        max_supported_version = max_ver;
                    }
                }
                _ => {}
            }

            pos = ext_data_end;
        }
    }

    // Determine effective TLS version
    let tls_version = if has_supported_versions && max_supported_version >= 0x0304 {
        TlsVersion::Tls13
    } else if client_version >= 0x0303 {
        TlsVersion::Tls12
    } else {
        TlsVersion::Tls12 // Default to 1.2 for anything we intercept
    };

    Some(ClientHelloFields {
        tls_version,
        cipher_suites,
        extensions,
        sni,
        supported_groups,
        alpn_protocols,
    })
}

fn parse_sni_extension(buf: &[u8]) -> Option<String> {
    // SNI list: total_length(2) + entries
    if buf.len() < 2 {
        return None;
    }
    let mut pos = 2; // skip SNI list length

    // First entry: type(1) + name_length(2) + name
    if buf.len() < pos + 3 {
        return None;
    }
    let _name_type = buf[pos];
    pos += 1;
    let name_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if buf.len() < pos + name_len {
        return None;
    }
    let name = std::str::from_utf8(&buf[pos..pos + name_len]).ok()?;
    Some(name.to_ascii_lowercase())
}

fn parse_u16_list(buf: &[u8]) -> Vec<u16> {
    if buf.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut result = Vec::with_capacity(list_len / 2);
    let mut pos = 2;
    let end = (2 + list_len).min(buf.len());
    while pos + 1 < end {
        result.push(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;
    }
    result
}

fn parse_alpn_extension(buf: &[u8]) -> Vec<String> {
    if buf.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut result = Vec::new();
    let mut pos = 2;
    let end = (2 + list_len).min(buf.len());
    while pos < end {
        let proto_len = buf[pos] as usize;
        pos += 1;
        if pos + proto_len > end {
            break;
        }
        if let Ok(proto) = std::str::from_utf8(&buf[pos..pos + proto_len]) {
            result.push(proto.to_string());
        }
        pos += proto_len;
    }
    result
}

fn parse_supported_versions(buf: &[u8]) -> Option<u16> {
    // Client: list_length(1) + versions
    if buf.is_empty() {
        return None;
    }
    let list_len = buf[0] as usize;
    let mut max_version: u16 = 0;
    let mut pos = 1;
    let end = (1 + list_len).min(buf.len());
    while pos + 1 < end {
        let ver = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        if !is_grease(ver) && ver > max_version {
            max_version = ver;
        }
        pos += 2;
    }
    Some(max_version)
}

// Inline hex encoder (avoid adding `hex` crate dep just for this)
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        result.push(HEX_CHARS[(b >> 4) as usize] as char);
        result.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values_detected() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0035));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn ja4_format_is_correct() {
        let fields = ClientHelloFields {
            tls_version: TlsVersion::Tls13,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            extensions: vec![0, 10, 11, 13, 16, 43, 45, 51],
            sni: Some("api.openai.com".to_string()),
            supported_groups: vec![29, 23, 24],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        let ja4 = compute_ja4(&fields);

        // Format: t{version}{sni}{alpn}{cipher_count}{ext_count}_{hash}_{hash}
        assert!(ja4.starts_with("t13dh2"), "got: {ja4}");
        // 3 ciphers, 6 extensions (8 - SNI(0) - ALPN(16) = 6)
        assert!(ja4.contains("0306_"), "got: {ja4}");
        // Two underscore-separated hash sections
        assert_eq!(ja4.matches('_').count(), 2, "got: {ja4}");
        // Total length: 10 (prefix) + 1 (_) + 12 (hash) + 1 (_) + 12 (hash) = 36
        assert_eq!(ja4.len(), 36, "got: {ja4}");
    }

    #[test]
    fn ja4_no_sni_no_alpn() {
        let fields = ClientHelloFields {
            tls_version: TlsVersion::Tls12,
            cipher_suites: vec![0x002f, 0x0035],
            extensions: vec![10, 11, 13],
            sni: None,
            supported_groups: vec![23],
            alpn_protocols: vec![],
        };
        let ja4 = compute_ja4(&fields);
        assert!(ja4.starts_with("t12i00"), "got: {ja4}");
        assert!(ja4.contains("0203_"), "got: {ja4}");
    }

    #[test]
    fn parse_minimal_clienthello() {
        // Build a minimal valid ClientHello record
        let mut record = Vec::new();

        // TLS Record header: Handshake(22), TLS 1.0 (0x0301), length placeholder
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        let length_pos = record.len();
        record.extend_from_slice(&[0x00, 0x00]); // placeholder

        // Handshake header: ClientHello(1), length placeholder
        record.push(1);
        let hs_length_pos = record.len();
        record.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder

        let body_start = record.len();

        // client_version: TLS 1.2 (0x0303)
        record.extend_from_slice(&[0x03, 0x03]);
        // random: 32 bytes
        record.extend_from_slice(&[0u8; 32]);
        // session_id: length 0
        record.push(0);
        // cipher_suites: 2 suites
        record.extend_from_slice(&[0x00, 0x04]); // 4 bytes = 2 suites
        record.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        record.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // Compression methods: 1 method (null)
        record.push(1);
        record.push(0);
        // No extensions
        record.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

        // Fix up lengths
        let body_len = record.len() - body_start;
        record[hs_length_pos] = ((body_len >> 16) & 0xff) as u8;
        record[hs_length_pos + 1] = ((body_len >> 8) & 0xff) as u8;
        record[hs_length_pos + 2] = (body_len & 0xff) as u8;

        let record_body_len = record.len() - 5;
        record[length_pos] = ((record_body_len >> 8) & 0xff) as u8;
        record[length_pos + 1] = (record_body_len & 0xff) as u8;

        let result = parse_client_hello(&record);
        assert!(result.is_some(), "should parse minimal ClientHello");

        let fields = result.unwrap();
        assert_eq!(fields.cipher_suites, vec![0x1301, 0x1302]);
        assert!(fields.sni.is_none());
        assert!(fields.alpn_protocols.is_empty());
    }

    #[test]
    fn non_handshake_returns_none() {
        // Application data record
        let buf = [23, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0];
        assert!(parse_client_hello(&buf).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        assert!(parse_client_hello(&[22, 0x03]).is_none());
        assert!(parse_client_hello(&[]).is_none());
    }

    #[test]
    fn fingerprint_round_trip() {
        let fields = ClientHelloFields {
            tls_version: TlsVersion::Tls13,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            extensions: vec![0, 10, 11, 13, 16, 43, 45, 51],
            sni: Some("api.anthropic.com".to_string()),
            supported_groups: vec![29, 23, 24],
            alpn_protocols: vec!["h2".to_string()],
        };

        let fp = build_fingerprint(&fields);
        assert!(fp.ja4.starts_with("t13dh2"));
        assert_eq!(fp.tls_version, TlsVersion::Tls13);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert!(!fp.ja3.is_empty());
    }
}
