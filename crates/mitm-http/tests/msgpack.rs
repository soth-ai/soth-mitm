use mitm_http::{
    DecoderFrame, DecoderStage, DecoderStageProcessor, DecoderStageStatus, LayeredDecoderPipeline,
    MsgPackDecodeLimits, MsgPackDecodeStage, CONTENT_TYPE_ATTRIBUTE, MSGPACK_CANDIDATE_ATTRIBUTE,
    MSGPACK_DECODED_ATTRIBUTE, MSGPACK_DETECTION_SOURCE_ATTRIBUTE, MSGPACK_FAILURE_CODE_ATTRIBUTE,
    MSGPACK_FALLBACK_ATTRIBUTE,
};
use std::collections::BTreeMap;

fn run_payload_stage(
    input: &[u8],
    content_type: Option<&str>,
    limits: MsgPackDecodeLimits,
) -> mitm_http::DecoderPipelineResult {
    let mut frame = DecoderFrame::new(input.to_vec(), true);
    if let Some(content_type) = content_type {
        frame
            .attributes
            .insert(CONTENT_TYPE_ATTRIBUTE.to_string(), content_type.to_string());
    }

    let mut processors: BTreeMap<DecoderStage, Box<dyn DecoderStageProcessor>> = BTreeMap::new();
    processors.insert(
        DecoderStage::PayloadParse,
        Box::new(MsgPackDecodeStage::new(limits)),
    );

    let mut pipeline = LayeredDecoderPipeline::new(vec![DecoderStage::PayloadParse], processors)
        .expect("pipeline");
    pipeline.execute(frame)
}

#[test]
fn content_type_candidate_decodes_valid_msgpack() {
    let payload = [0x81, 0xa1, b'k', 0xa1, b'v'];
    let result = run_payload_stage(
        &payload,
        Some("application/msgpack"),
        MsgPackDecodeLimits::default(),
    );
    assert!(result.failure.is_none());
    assert_eq!(result.reports.len(), 1);
    assert_eq!(result.reports[0].status, DecoderStageStatus::Applied);
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_CANDIDATE_ATTRIBUTE)
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_DETECTION_SOURCE_ATTRIBUTE)
            .map(String::as_str),
        Some("content_type")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_DECODED_ATTRIBUTE)
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(result.output.bytes, payload);
    assert!(!result
        .output
        .attributes
        .contains_key(MSGPACK_FALLBACK_ATTRIBUTE));
}

#[test]
fn heuristic_candidate_decodes_when_prefix_matches() {
    let payload = [0x92, 0x01, 0x02];
    let result = run_payload_stage(&payload, None, MsgPackDecodeLimits::default());
    assert!(result.failure.is_none());
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_DETECTION_SOURCE_ATTRIBUTE)
            .map(String::as_str),
        Some("heuristic")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_DECODED_ATTRIBUTE)
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn malformed_candidate_falls_back_to_raw_bytes() {
    let payload = [0xc1];
    let result = run_payload_stage(
        &payload,
        Some("application/x-msgpack"),
        MsgPackDecodeLimits::default(),
    );
    assert!(result.failure.is_none());
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_DECODED_ATTRIBUTE)
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_FALLBACK_ATTRIBUTE)
            .map(String::as_str),
        Some("raw")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_FAILURE_CODE_ATTRIBUTE)
            .map(String::as_str),
        Some("invalid_marker")
    );
    assert_eq!(result.output.bytes, payload);
}

#[test]
fn oversized_candidate_falls_back_to_raw_bytes() {
    let payload = [0x92, 0x01, 0x02];
    let limits = MsgPackDecodeLimits {
        max_input_bytes: 2,
        ..MsgPackDecodeLimits::default()
    };
    let result = run_payload_stage(&payload, Some("application/msgpack"), limits);
    assert!(result.failure.is_none());
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_FAILURE_CODE_ATTRIBUTE)
            .map(String::as_str),
        Some("input_too_large")
    );
    assert_eq!(result.output.bytes, payload);
}

#[test]
fn container_limit_violation_falls_back_to_raw_bytes() {
    let payload = [0x92, 0x01, 0x02];
    let limits = MsgPackDecodeLimits {
        max_container_len: 1,
        ..MsgPackDecodeLimits::default()
    };
    let result = run_payload_stage(&payload, Some("application/msgpack"), limits);
    assert!(result.failure.is_none());
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_FAILURE_CODE_ATTRIBUTE)
            .map(String::as_str),
        Some("container_too_large")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_FALLBACK_ATTRIBUTE)
            .map(String::as_str),
        Some("raw")
    );
    assert_eq!(result.output.bytes, payload);
}

#[test]
fn non_candidate_payload_stays_raw_without_error_code() {
    let payload = br#"{"plain":true}"#;
    let result = run_payload_stage(
        payload,
        Some("application/json"),
        MsgPackDecodeLimits::default(),
    );
    assert!(result.failure.is_none());
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_CANDIDATE_ATTRIBUTE)
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_DECODED_ATTRIBUTE)
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .output
            .attributes
            .get(MSGPACK_FALLBACK_ATTRIBUTE)
            .map(String::as_str),
        Some("raw")
    );
    assert!(!result
        .output
        .attributes
        .contains_key(MSGPACK_FAILURE_CODE_ATTRIBUTE));
    assert_eq!(result.output.bytes, payload);
}
