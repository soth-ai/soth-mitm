use mitm_http::{GrpcEnvelopeMalformedCode, GrpcEnvelopeParser, GrpcEnvelopeRecord};
use proptest::prelude::*;

fn frame(compressed_flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(compressed_flag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

proptest! {
    #[test]
    fn frame_round_trips_under_arbitrary_split(
        payload in proptest::collection::vec(any::<u8>(), 0..256),
        split in 0_usize..512,
    ) {
        let encoded = frame(0, &payload);
        let split_at = split.min(encoded.len());

        let mut parser = GrpcEnvelopeParser::default();
        let mut records = Vec::new();
        records.extend(parser.push_chunk(&encoded[..split_at]));
        records.extend(parser.push_chunk(&encoded[split_at..]));

        prop_assert_eq!(records.len(), 1);
        match &records[0] {
            GrpcEnvelopeRecord::Frame(record) => {
                prop_assert_eq!(record.sequence_no, 1);
                prop_assert!(!record.compressed);
                prop_assert_eq!(record.message_len, payload.len());
            }
            GrpcEnvelopeRecord::Malformed(other) => {
                prop_assert!(false, "unexpected malformed record: {}", other.code.as_str());
            }
        }
        prop_assert!(parser.finish().is_none());
    }

    #[test]
    fn invalid_compressed_flag_is_classified(
        payload in proptest::collection::vec(any::<u8>(), 0..64),
        flag in 2_u8..=u8::MAX,
    ) {
        let encoded = frame(flag, &payload);
        let mut parser = GrpcEnvelopeParser::default();
        let records = parser.push_chunk(&encoded);

        prop_assert_eq!(records.len(), 1);
        match &records[0] {
            GrpcEnvelopeRecord::Malformed(malformed) => {
                prop_assert_eq!(malformed.code, GrpcEnvelopeMalformedCode::InvalidCompressedFlag);
                prop_assert_eq!(malformed.frame_sequence_no, 1);
                prop_assert_eq!(malformed.declared_message_len, Some(payload.len()));
            }
            GrpcEnvelopeRecord::Frame(_) => {
                prop_assert!(false, "invalid compressed flag must not parse as frame");
            }
        }
    }

    #[test]
    fn truncated_body_emits_length_mismatch_on_finish(
        payload in proptest::collection::vec(any::<u8>(), 1..128),
        missing_bytes in 1_usize..128,
    ) {
        let encoded = frame(0, &payload);
        let drop = missing_bytes.min(payload.len());
        let retained_len = 5 + payload.len() - drop;
        let truncated = &encoded[..retained_len];

        let mut parser = GrpcEnvelopeParser::default();
        let records = parser.push_chunk(truncated);
        prop_assert!(records.is_empty());

        let malformed = parser.finish().expect("expected length mismatch");
        prop_assert_eq!(malformed.code, GrpcEnvelopeMalformedCode::LengthMismatch);
        prop_assert_eq!(malformed.frame_sequence_no, 1);
        prop_assert_eq!(malformed.declared_message_len, Some(payload.len()));
        prop_assert_eq!(malformed.remaining_body_bytes, Some(drop));
    }
}
