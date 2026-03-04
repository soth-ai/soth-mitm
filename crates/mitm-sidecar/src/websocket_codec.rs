#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebSocketHeaderView {
    fin: bool,
    opcode: u8,
    masked: bool,
    mask: Option<u32>,
    payload_len: usize,
    header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebSocketHeaderDecodeResult {
    NeedMore(usize),
    Complete(WebSocketHeaderView),
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketClosePayload {
    code: Option<u16>,
    reason: Option<String>,
}

fn decode_websocket_header_soketto(
    codec: &soketto::base::Codec,
    bytes: &[u8],
) -> io::Result<WebSocketHeaderDecodeResult> {
    match codec.decode_header(bytes) {
        Ok(soketto::Parsing::NeedMore(needed)) => Ok(WebSocketHeaderDecodeResult::NeedMore(needed)),
        Ok(soketto::Parsing::Done { value, offset }) => {
            let opcode = value.opcode().into();
            let masked = value.is_masked();
            let mask = if masked { Some(value.mask()) } else { None };
            Ok(WebSocketHeaderDecodeResult::Complete(WebSocketHeaderView {
                fin: value.is_fin(),
                opcode,
                masked,
                mask,
                payload_len: value.payload_len(),
                header_len: offset,
            }))
        }
        Err(error) => Err(soketto_codec_error_to_io("decode_header", error)),
    }
}

#[cfg(test)]
fn encode_websocket_header_soketto(
    fin: bool,
    opcode: u8,
    masked: bool,
    mask: Option<u32>,
    payload_len: usize,
) -> io::Result<Vec<u8>> {
    let opcode = websocket_opcode_from_u8(opcode)?;
    if masked && mask.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_codec:encode_header:missing_mask_key",
        ));
    }
    if !masked && mask.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket_codec:encode_header:unexpected_mask_key",
        ));
    }

    let mut header = soketto::base::Header::new(opcode);
    header.set_fin(fin);
    header.set_masked(masked);
    if let Some(mask_key) = mask {
        header.set_mask(mask_key);
    }
    header.set_payload_len(payload_len);

    let mut codec = soketto::base::Codec::new();
    Ok(codec.encode_header(&header).to_vec())
}

fn validate_websocket_mask_direction(
    direction: mitm_http::WsDirection,
    masked: bool,
) -> io::Result<()> {
    match direction {
        mitm_http::WsDirection::ClientToServer if !masked => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket_mask_direction:client_frame_unmasked",
        )),
        mitm_http::WsDirection::ServerToClient if masked => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket_mask_direction:server_frame_masked",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
fn parse_websocket_close_payload(payload: &[u8]) -> io::Result<WebSocketClosePayload> {
    if payload.is_empty() {
        return Ok(WebSocketClosePayload {
            code: None,
            reason: None,
        });
    }
    if payload.len() == 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket_close_payload:truncated_code",
        ));
    }

    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !is_valid_websocket_close_code(code) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_close_payload:invalid_code:{code}"),
        ));
    }

    let reason = if payload.len() > 2 {
        let decoded = std::str::from_utf8(&payload[2..]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("websocket_close_payload:invalid_utf8:{error}"),
            )
        })?;
        if decoded.is_empty() {
            None
        } else {
            Some(decoded.to_string())
        }
    } else {
        None
    };

    Ok(WebSocketClosePayload {
        code: Some(code),
        reason,
    })
}

#[cfg(test)]
fn websocket_opcode_from_u8(opcode: u8) -> io::Result<soketto::base::OpCode> {
    soketto::base::OpCode::try_from(opcode).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:invalid_opcode:{opcode}"),
        )
    })
}

#[cfg(test)]
fn is_valid_websocket_close_code(code: u16) -> bool {
    matches!(
        code,
        1000..=1003 | 1007..=1011 | 1012 | 1013 | 1015 | 3000..=4999
    )
}

fn soketto_codec_error_to_io(stage: &'static str, error: soketto::base::Error) -> io::Error {
    match error {
        soketto::base::Error::Io(inner) => io::Error::new(
            inner.kind(),
            format!("websocket_codec:{stage}:io:{inner}"),
        ),
        soketto::base::Error::UnknownOpCode => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:unknown_opcode"),
        ),
        soketto::base::Error::ReservedOpCode => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:reserved_opcode"),
        ),
        soketto::base::Error::FragmentedControl => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:fragmented_control_frame"),
        ),
        soketto::base::Error::InvalidControlFrameLen => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:invalid_control_frame_len"),
        ),
        soketto::base::Error::InvalidReservedBit(bit) => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:invalid_reserved_bit:{bit}"),
        ),
        soketto::base::Error::PayloadTooLarge { actual, maximum } => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:payload_too_large:{actual}:{maximum}"),
        ),
        _ => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:{stage}:unclassified_error"),
        ),
    }
}

#[cfg(test)]
mod websocket_codec_tests {
    use std::io;

    use super::{
        decode_websocket_header_soketto, encode_websocket_header_soketto,
        parse_websocket_close_payload, validate_websocket_mask_direction, WebSocketHeaderDecodeResult,
    };

    #[test]
    fn decode_header_reports_need_more_for_incomplete_header() {
        let codec = soketto::base::Codec::new();
        let decoded = decode_websocket_header_soketto(&codec, &[0x81]).expect("decode should succeed");
        assert_eq!(decoded, WebSocketHeaderDecodeResult::NeedMore(1));
    }

    #[test]
    fn decode_header_rejects_reserved_opcode() {
        let codec = soketto::base::Codec::new();
        let error =
            decode_websocket_header_soketto(&codec, &[0x83, 0x00]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("reserved_opcode"));
    }

    #[test]
    fn decode_header_rejects_invalid_reserved_bit() {
        let codec = soketto::base::Codec::new();
        let error =
            decode_websocket_header_soketto(&codec, &[0xC1, 0x00]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid_reserved_bit:1"));
    }

    #[test]
    fn decode_header_rejects_fragmented_control_frame() {
        let codec = soketto::base::Codec::new();
        let error =
            decode_websocket_header_soketto(&codec, &[0x09, 0x00]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("fragmented_control_frame"));
    }

    #[test]
    fn decode_header_rejects_control_frame_payload_over_125() {
        let codec = soketto::base::Codec::new();
        let error = decode_websocket_header_soketto(&codec, &[0x89, 0x7E, 0x00, 0x7E])
            .expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid_control_frame_len"));
    }

    #[test]
    fn decode_header_rejects_payload_over_configured_limit() {
        let mut codec = soketto::base::Codec::new();
        codec.set_max_data_size(1);
        let error =
            decode_websocket_header_soketto(&codec, &[0x82, 0x02]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("payload_too_large"));
    }

    #[test]
    fn encode_and_decode_header_roundtrip() {
        let header = encode_websocket_header_soketto(true, 0x1, true, Some(0x0102_0304), 5)
            .expect("encode should succeed");
        let codec = soketto::base::Codec::new();
        let decoded = decode_websocket_header_soketto(&codec, &header).expect("decode");
        let WebSocketHeaderDecodeResult::Complete(decoded) = decoded else {
            panic!("expected complete header decode");
        };

        assert!(decoded.fin);
        assert_eq!(decoded.opcode, 0x1);
        assert!(decoded.masked);
        assert_eq!(decoded.mask, Some(0x0102_0304));
        assert_eq!(decoded.payload_len, 5);
    }

    #[test]
    fn encode_header_rejects_missing_mask_key() {
        let error = encode_websocket_header_soketto(true, 0x1, true, None, 5)
            .expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("missing_mask_key"));
    }

    #[test]
    fn validate_mask_direction_requires_client_frames_to_be_masked() {
        let error = validate_websocket_mask_direction(
            mitm_http::WsDirection::ClientToServer,
            false,
        )
        .expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("client_frame_unmasked"));
    }

    #[test]
    fn validate_mask_direction_rejects_masked_server_frames() {
        let error = validate_websocket_mask_direction(
            mitm_http::WsDirection::ServerToClient,
            true,
        )
        .expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("server_frame_masked"));
    }

    #[test]
    fn parse_close_payload_handles_empty_payload() {
        let payload = parse_websocket_close_payload(&[]).expect("parse should succeed");
        assert_eq!(payload.code, None);
        assert_eq!(payload.reason, None);
    }

    #[test]
    fn parse_close_payload_rejects_truncated_code() {
        let error = parse_websocket_close_payload(&[0x03]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("truncated_code"));
    }

    #[test]
    fn parse_close_payload_rejects_invalid_code() {
        let error = parse_websocket_close_payload(&[0x03, 0xEC]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid_code:1004"));
    }

    #[test]
    fn parse_close_payload_rejects_invalid_utf8_reason() {
        let error = parse_websocket_close_payload(&[0x03, 0xE8, 0xFF]).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid_utf8"));
    }

    #[test]
    fn parse_close_payload_parses_valid_code_and_reason() {
        let payload = parse_websocket_close_payload(&[0x03, 0xE8, b'o', b'k'])
            .expect("parse should succeed");
        assert_eq!(payload.code, Some(1000));
        assert_eq!(payload.reason.as_deref(), Some("ok"));
    }
}
