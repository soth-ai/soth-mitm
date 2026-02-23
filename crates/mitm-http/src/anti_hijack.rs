use crate::{DecoderFrame, DecoderStageProcessor, StageProcessOutcome};

pub const SANITIZED_ATTRIBUTE: &str = "sanitized";
pub const SANITIZED_PREFIX_ATTRIBUTE: &str = "sanitized_prefix";
pub const SANITIZED_PROVENANCE_ATTRIBUTE: &str = "sanitized_provenance";

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiHijackPrefix {
    pub name: &'static str,
    pub bytes: &'static [u8],
}

impl AntiHijackPrefix {
    pub const fn new(name: &'static str, bytes: &'static [u8]) -> Self {
        Self { name, bytes }
    }
}

pub const KNOWN_ANTI_HIJACK_PREFIXES: [AntiHijackPrefix; 6] = [
    AntiHijackPrefix::new("xssi_angular_prefix_lf", b")]}'\n"),
    AntiHijackPrefix::new("xssi_angular_prefix_crlf", b")]}'\r\n"),
    AntiHijackPrefix::new("xssi_angular_prefix", b")]}'"),
    AntiHijackPrefix::new("while_1_prefix", b"while(1);"),
    AntiHijackPrefix::new("for_ever_prefix_compact", b"for(;;);"),
    AntiHijackPrefix::new("for_ever_prefix_spaced", b"for (;;);"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiHijackSanitizeResult {
    pub bytes: Vec<u8>,
    pub sanitized: bool,
    pub sanitized_prefix: Option<&'static str>,
}

impl AntiHijackSanitizeResult {
    fn unsanitized(input: &[u8]) -> Self {
        Self {
            bytes: input.to_vec(),
            sanitized: false,
            sanitized_prefix: None,
        }
    }
}

pub fn sanitize_anti_hijack_prefix(input: &[u8]) -> AntiHijackSanitizeResult {
    sanitize_anti_hijack_prefixes(input, &KNOWN_ANTI_HIJACK_PREFIXES)
}

pub fn sanitize_anti_hijack_prefixes(
    input: &[u8],
    prefixes: &[AntiHijackPrefix],
) -> AntiHijackSanitizeResult {
    let prefix_start = scan_prefix_start(input);
    if prefix_start >= input.len() {
        return AntiHijackSanitizeResult::unsanitized(input);
    }

    for prefix in prefixes {
        if !input[prefix_start..].starts_with(prefix.bytes) {
            continue;
        }
        let payload_start = prefix_start + prefix.bytes.len();
        let first_payload_byte = skip_ascii_whitespace(input, payload_start);
        if first_payload_byte >= input.len() || !is_json_payload_start(input[first_payload_byte]) {
            continue;
        }

        let mut out = Vec::with_capacity(input.len().saturating_sub(prefix.bytes.len()));
        out.extend_from_slice(&input[..prefix_start]);
        out.extend_from_slice(&input[payload_start..]);
        return AntiHijackSanitizeResult {
            bytes: out,
            sanitized: true,
            sanitized_prefix: Some(prefix.name),
        };
    }

    AntiHijackSanitizeResult::unsanitized(input)
}

#[derive(Debug, Clone)]
pub struct AntiHijackSanitizationStage {
    prefixes: Vec<AntiHijackPrefix>,
}

impl Default for AntiHijackSanitizationStage {
    fn default() -> Self {
        Self::with_known_prefixes()
    }
}

impl AntiHijackSanitizationStage {
    pub fn new(prefixes: Vec<AntiHijackPrefix>) -> Self {
        Self { prefixes }
    }

    pub fn with_known_prefixes() -> Self {
        Self {
            prefixes: KNOWN_ANTI_HIJACK_PREFIXES.to_vec(),
        }
    }

    pub fn prefixes(&self) -> &[AntiHijackPrefix] {
        &self.prefixes
    }
}

impl DecoderStageProcessor for AntiHijackSanitizationStage {
    fn process(&mut self, frame: &DecoderFrame) -> Result<StageProcessOutcome, String> {
        let sanitized = sanitize_anti_hijack_prefixes(&frame.bytes, &self.prefixes);
        let mut next = frame.clone();
        next.bytes = sanitized.bytes;
        next.attributes.insert(
            SANITIZED_ATTRIBUTE.to_string(),
            sanitized.sanitized.to_string(),
        );
        if let Some(prefix) = sanitized.sanitized_prefix {
            next.attributes
                .insert(SANITIZED_PREFIX_ATTRIBUTE.to_string(), prefix.to_string());
            next.attributes.insert(
                SANITIZED_PROVENANCE_ATTRIBUTE.to_string(),
                format!("anti_hijack_prefix:{prefix}"),
            );
        } else {
            next.attributes.remove(SANITIZED_PREFIX_ATTRIBUTE);
            next.attributes.remove(SANITIZED_PROVENANCE_ATTRIBUTE);
        }
        Ok(StageProcessOutcome::Applied(next))
    }
}

fn scan_prefix_start(input: &[u8]) -> usize {
    let mut offset = 0;
    if input.starts_with(UTF8_BOM) {
        offset = UTF8_BOM.len();
    }
    skip_ascii_whitespace(input, offset)
}

fn skip_ascii_whitespace(input: &[u8], mut offset: usize) -> usize {
    while offset < input.len() && input[offset].is_ascii_whitespace() {
        offset += 1;
    }
    offset
}

fn is_json_payload_start(byte: u8) -> bool {
    matches!(
        byte,
        b'{' | b'[' | b'"' | b't' | b'f' | b'n' | b'-' | b'0'..=b'9'
    )
}

#[cfg(test)]
mod tests {
    use super::{
        sanitize_anti_hijack_prefix, AntiHijackSanitizationStage, SANITIZED_ATTRIBUTE,
        SANITIZED_PROVENANCE_ATTRIBUTE,
    };
    use crate::{DecoderFrame, DecoderStageProcessor, StageProcessOutcome};

    #[test]
    fn strips_known_prefix_before_json_payload() {
        let input = b")]}'\n{\"ok\":true}";
        let sanitized = sanitize_anti_hijack_prefix(input);
        assert!(sanitized.sanitized);
        assert_eq!(sanitized.sanitized_prefix, Some("xssi_angular_prefix_lf"));
        assert_eq!(sanitized.bytes, b"{\"ok\":true}");
    }

    #[test]
    fn preserves_normal_json_without_prefix() {
        let input = b"{\"ok\":true}";
        let sanitized = sanitize_anti_hijack_prefix(input);
        assert!(!sanitized.sanitized);
        assert_eq!(sanitized.sanitized_prefix, None);
        assert_eq!(sanitized.bytes, input);
    }

    #[test]
    fn does_not_strip_non_json_payload_after_prefix() {
        let input = b"while(1);window.steal()";
        let sanitized = sanitize_anti_hijack_prefix(input);
        assert!(!sanitized.sanitized);
        assert_eq!(sanitized.bytes, input);
    }

    #[test]
    fn stage_sets_sanitization_metadata() {
        let mut stage = AntiHijackSanitizationStage::default();
        let frame = DecoderFrame::new(b"while(1);{\"model\":\"gpt\"}".to_vec(), true);
        let StageProcessOutcome::Applied(next) = stage.process(&frame).expect("must succeed")
        else {
            panic!("stage must always apply");
        };
        assert_eq!(
            next.attributes.get(SANITIZED_ATTRIBUTE).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            next.attributes
                .get(SANITIZED_PROVENANCE_ATTRIBUTE)
                .map(String::as_str),
            Some("anti_hijack_prefix:while_1_prefix")
        );
        assert_eq!(next.bytes, b"{\"model\":\"gpt\"}");
    }
}
