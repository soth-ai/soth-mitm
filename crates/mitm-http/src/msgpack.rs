use crate::msgpack_parser::decode_msgpack_structure_impl;
use crate::{DecoderFrame, DecoderStageProcessor, StageProcessOutcome};

pub const CONTENT_TYPE_ATTRIBUTE: &str = "content_type";
pub const MSGPACK_CANDIDATE_ATTRIBUTE: &str = "msgpack_candidate";
pub const MSGPACK_DECODED_ATTRIBUTE: &str = "msgpack_decoded";
pub const MSGPACK_DETECTION_SOURCE_ATTRIBUTE: &str = "msgpack_detection_source";
pub const MSGPACK_FAILURE_CODE_ATTRIBUTE: &str = "msgpack_failure_code";
pub const MSGPACK_FAILURE_DETAIL_ATTRIBUTE: &str = "msgpack_failure_detail";
pub const MSGPACK_FALLBACK_ATTRIBUTE: &str = "msgpack_fallback";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgPackDecodeLimits {
    pub max_input_bytes: usize,
    pub max_depth: usize,
    pub max_container_len: usize,
    pub max_text_bytes: usize,
    pub max_binary_bytes: usize,
    pub max_extension_bytes: usize,
}

impl Default for MsgPackDecodeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 4 * 1024 * 1024,
            max_depth: 64,
            max_container_len: 65_536,
            max_text_bytes: 2 * 1024 * 1024,
            max_binary_bytes: 2 * 1024 * 1024,
            max_extension_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgPackDetectionSource {
    ContentType,
    Heuristic,
}

impl MsgPackDetectionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContentType => "content_type",
            Self::Heuristic => "heuristic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgPackFailureCode {
    InputTooLarge,
    DepthExceeded,
    ContainerTooLarge,
    TextTooLarge,
    BinaryTooLarge,
    ExtensionTooLarge,
    Truncated,
    InvalidMarker,
    TrailingBytes,
}

impl MsgPackFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::DepthExceeded => "depth_exceeded",
            Self::ContainerTooLarge => "container_too_large",
            Self::TextTooLarge => "text_too_large",
            Self::BinaryTooLarge => "binary_too_large",
            Self::ExtensionTooLarge => "extension_too_large",
            Self::Truncated => "truncated",
            Self::InvalidMarker => "invalid_marker",
            Self::TrailingBytes => "trailing_bytes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgPackDecodeFailure {
    pub code: MsgPackFailureCode,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgPackDetection {
    pub candidate: bool,
    pub source: Option<MsgPackDetectionSource>,
}

#[derive(Debug, Clone, Default)]
pub struct MsgPackDecodeStage {
    limits: MsgPackDecodeLimits,
}

impl MsgPackDecodeStage {
    pub fn new(limits: MsgPackDecodeLimits) -> Self {
        Self { limits }
    }

    pub fn limits(&self) -> MsgPackDecodeLimits {
        self.limits
    }
}

impl DecoderStageProcessor for MsgPackDecodeStage {
    fn process(&mut self, frame: &DecoderFrame) -> Result<StageProcessOutcome, String> {
        let mut next = frame.clone();
        let content_type = frame
            .attributes
            .get(CONTENT_TYPE_ATTRIBUTE)
            .map(String::as_str);
        let detection = detect_msgpack_candidate(content_type, &frame.bytes);

        next.attributes.insert(
            MSGPACK_CANDIDATE_ATTRIBUTE.to_string(),
            detection.candidate.to_string(),
        );
        if let Some(source) = detection.source {
            next.attributes.insert(
                MSGPACK_DETECTION_SOURCE_ATTRIBUTE.to_string(),
                source.as_str().to_string(),
            );
        } else {
            next.attributes.remove(MSGPACK_DETECTION_SOURCE_ATTRIBUTE);
        }

        if !detection.candidate {
            set_raw_fallback_attributes(&mut next, None);
            return Ok(StageProcessOutcome::Applied(next));
        }

        match decode_msgpack_structure(&frame.bytes, self.limits) {
            Ok(()) => {
                next.attributes
                    .insert(MSGPACK_DECODED_ATTRIBUTE.to_string(), "true".to_string());
                next.attributes.remove(MSGPACK_FAILURE_CODE_ATTRIBUTE);
                next.attributes.remove(MSGPACK_FAILURE_DETAIL_ATTRIBUTE);
                next.attributes.remove(MSGPACK_FALLBACK_ATTRIBUTE);
            }
            Err(failure) => {
                set_raw_fallback_attributes(&mut next, Some(&failure));
            }
        }

        Ok(StageProcessOutcome::Applied(next))
    }
}

pub fn is_msgpack_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/msgpack" | "application/x-msgpack" | "application/vnd.msgpack"
    )
}

pub fn looks_like_msgpack_prefix(input: &[u8]) -> bool {
    let Some(lead) = input.first().copied() else {
        return false;
    };
    matches!(
        lead,
        0x80..=0x8f
            | 0x90..=0x9f
            | 0xa0..=0xbf
            | 0xc4..=0xc9
            | 0xca..=0xcb
            | 0xcc..=0xcf
            | 0xd0..=0xd3
            | 0xd4..=0xd8
            | 0xd9..=0xdb
            | 0xdc..=0xdf
    )
}

pub fn detect_msgpack_candidate(content_type: Option<&str>, input: &[u8]) -> MsgPackDetection {
    if content_type.is_some_and(is_msgpack_content_type) {
        return MsgPackDetection {
            candidate: true,
            source: Some(MsgPackDetectionSource::ContentType),
        };
    }
    if looks_like_msgpack_prefix(input) {
        return MsgPackDetection {
            candidate: true,
            source: Some(MsgPackDetectionSource::Heuristic),
        };
    }
    MsgPackDetection {
        candidate: false,
        source: None,
    }
}

pub fn decode_msgpack_structure(
    input: &[u8],
    limits: MsgPackDecodeLimits,
) -> Result<(), MsgPackDecodeFailure> {
    decode_msgpack_structure_impl(input, limits)
}

fn set_raw_fallback_attributes(frame: &mut DecoderFrame, failure: Option<&MsgPackDecodeFailure>) {
    frame
        .attributes
        .insert(MSGPACK_DECODED_ATTRIBUTE.to_string(), "false".to_string());
    frame
        .attributes
        .insert(MSGPACK_FALLBACK_ATTRIBUTE.to_string(), "raw".to_string());
    if let Some(failure) = failure {
        frame.attributes.insert(
            MSGPACK_FAILURE_CODE_ATTRIBUTE.to_string(),
            failure.code.as_str().to_string(),
        );
        frame.attributes.insert(
            MSGPACK_FAILURE_DETAIL_ATTRIBUTE.to_string(),
            failure.detail.clone(),
        );
    } else {
        frame.attributes.remove(MSGPACK_FAILURE_CODE_ATTRIBUTE);
        frame.attributes.remove(MSGPACK_FAILURE_DETAIL_ATTRIBUTE);
    }
}
