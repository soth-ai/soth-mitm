use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WebSocketHeaderView {
    pub(crate) fin: bool,
    pub(crate) opcode: u8,
    pub(crate) masked: bool,
    pub(crate) mask: Option<u32>,
    pub(crate) payload_len: usize,
    pub(crate) header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebSocketHeaderDecodeResult {
    NeedMore(usize),
    Complete(WebSocketHeaderView),
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketClosePayload {
    code: Option<u16>,
    reason: Option<String>,
}

pub(crate) fn decode_websocket_header_soketto(
    _codec: &soketto::base::Codec,
    bytes: &[u8],
) -> io::Result<WebSocketHeaderDecodeResult> {
    const BASE_HEADER_LEN: usize = 2;
    if bytes.len() < BASE_HEADER_LEN {
        return Ok(WebSocketHeaderDecodeResult::NeedMore(
            BASE_HEADER_LEN - bytes.len(),
        ));
    }

    let first = bytes[0];
    let second = bytes[1];
    let fin = (first & 0x80) != 0;
    let opcode = first & 0x0F;
    let masked = (second & 0x80) != 0;

    let payload_len_code = (second & 0x7F) as usize;
    let (payload_len, mut header_len) = match payload_len_code {
        126 => {
            let required = 4;
            if bytes.len() < required {
                return Ok(WebSocketHeaderDecodeResult::NeedMore(
                    required - bytes.len(),
                ));
            }
            (u16::from_be_bytes([bytes[2], bytes[3]]) as usize, required)
        }
        127 => {
            let required = 10;
            if bytes.len() < required {
                return Ok(WebSocketHeaderDecodeResult::NeedMore(
                    required - bytes.len(),
                ));
            }
            let parsed = u64::from_be_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]);
            let parsed = usize::try_from(parsed).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "websocket_codec:decode_header:payload_length_overflow",
                )
            })?;
            (parsed, required)
        }
        _ => (payload_len_code, BASE_HEADER_LEN),
    };

    let mask = if masked {
        let required = header_len + 4;
        if bytes.len() < required {
            return Ok(WebSocketHeaderDecodeResult::NeedMore(
                required - bytes.len(),
            ));
        }
        header_len = required;
        Some(u32::from_be_bytes([
            bytes[header_len - 4],
            bytes[header_len - 3],
            bytes[header_len - 2],
            bytes[header_len - 1],
        ]))
    } else {
        None
    };

    Ok(WebSocketHeaderDecodeResult::Complete(WebSocketHeaderView {
        fin,
        opcode,
        masked,
        mask,
        payload_len,
        header_len,
    }))
}

pub(crate) fn websocket_payload_len_within_limit(
    payload_len: usize,
    max_frame_payload_bytes: usize,
) -> io::Result<()> {
    if payload_len > max_frame_payload_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "websocket_codec:decode_header:payload_too_large:{}:{}",
                payload_len, max_frame_payload_bytes
            ),
        ));
    }
    Ok(())
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

pub(crate) fn validate_websocket_mask_direction(
    direction: crate::protocol::WsDirection,
    masked: bool,
) -> io::Result<()> {
    match direction {
        crate::protocol::WsDirection::ClientToServer if !masked => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket_codec:client_frame_unmasked",
        )),
        crate::protocol::WsDirection::ServerToClient if masked => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket_codec:server_frame_masked",
        )),
        _ => Ok(()),
    }
}

pub(crate) fn validate_websocket_frame_rfc6455(fin: bool, opcode: u8) -> io::Result<()> {
    let is_control = (opcode & 0x8) != 0;
    if is_control && !fin {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket_codec:fragmented_control_frame",
        ));
    }
    let is_known = matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA);
    if !is_known {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket_codec:reserved_opcode:{opcode:#x}"),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod websocket_codec_tests {
    use std::io;

    use super::{
        decode_websocket_header_soketto, encode_websocket_header_soketto,
        parse_websocket_close_payload, validate_websocket_mask_direction,
        WebSocketHeaderDecodeResult,
    };

    #[test]
    fn decode_header_reports_need_more_for_incomplete_header() {
        let codec = soketto::base::Codec::new();
        let decoded =
            decode_websocket_header_soketto(&codec, &[0x81]).expect("decode should succeed");
        assert_eq!(decoded, WebSocketHeaderDecodeResult::NeedMore(1));
    }

    #[test]
    fn decode_header_accepts_reserved_opcode_for_passthrough() {
        let codec = soketto::base::Codec::new();
        let decoded =
            decode_websocket_header_soketto(&codec, &[0x83, 0x00]).expect("decode should succeed");
        let WebSocketHeaderDecodeResult::Complete(view) = decoded else {
            panic!("expected complete header decode");
        };
        assert!(view.fin);
        assert_eq!(view.opcode, 0x3);
        assert!(!view.masked);
        assert_eq!(view.payload_len, 0);
    }

    #[test]
    fn decode_header_accepts_reserved_bit_for_passthrough() {
        let codec = soketto::base::Codec::new();
        let decoded =
            decode_websocket_header_soketto(&codec, &[0xC1, 0x00]).expect("decode should succeed");
        let WebSocketHeaderDecodeResult::Complete(view) = decoded else {
            panic!("expected complete header decode");
        };
        assert!(view.fin);
        assert_eq!(view.opcode, 0x1);
        assert!(!view.masked);
        assert_eq!(view.payload_len, 0);
    }

    #[test]
    fn decode_header_accepts_fragmented_control_frame_for_passthrough() {
        let codec = soketto::base::Codec::new();
        let decoded =
            decode_websocket_header_soketto(&codec, &[0x09, 0x00]).expect("decode should succeed");
        let WebSocketHeaderDecodeResult::Complete(view) = decoded else {
            panic!("expected complete header decode");
        };
        assert!(!view.fin);
        assert_eq!(view.opcode, 0x9);
    }

    #[test]
    fn decode_header_accepts_control_frame_payload_over_125_for_passthrough() {
        let codec = soketto::base::Codec::new();
        let decoded = decode_websocket_header_soketto(&codec, &[0x89, 0x7E, 0x00, 0x7E])
            .expect("decode should succeed");
        let WebSocketHeaderDecodeResult::Complete(view) = decoded else {
            panic!("expected complete header decode");
        };
        assert_eq!(view.payload_len, 126);
    }

    #[test]
    fn payload_limit_enforcement_rejects_oversized_frame() {
        let error = super::websocket_payload_len_within_limit(2, 1).expect_err("must fail");
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
        let error =
            encode_websocket_header_soketto(true, 0x1, true, None, 5).expect_err("must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("missing_mask_key"));
    }

    #[test]
    fn validate_mask_direction_rejects_unmasked_client_frame() {
        let error =
            validate_websocket_mask_direction(crate::protocol::WsDirection::ClientToServer, false)
                .expect_err("unmasked client frame must fail");
        assert!(error.to_string().contains("client_frame_unmasked"));
    }

    #[test]
    fn validate_mask_direction_rejects_masked_server_frame() {
        let error =
            validate_websocket_mask_direction(crate::protocol::WsDirection::ServerToClient, true)
                .expect_err("masked server frame must fail");
        assert!(error.to_string().contains("server_frame_masked"));
    }

    #[test]
    fn validate_mask_direction_accepts_valid_frames() {
        validate_websocket_mask_direction(crate::protocol::WsDirection::ClientToServer, true)
            .expect("masked client frame should pass");
        validate_websocket_mask_direction(crate::protocol::WsDirection::ServerToClient, false)
            .expect("unmasked server frame should pass");
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
        let payload =
            parse_websocket_close_payload(&[0x03, 0xE8, b'o', b'k']).expect("parse should succeed");
        assert_eq!(payload.code, Some(1000));
        assert_eq!(payload.reason.as_deref(), Some("ok"));
    }

    #[test]
    fn validate_rfc6455_rejects_fragmented_control_frame() {
        let error = super::validate_websocket_frame_rfc6455(false, 0x9)
            .expect_err("fragmented ping must fail");
        assert!(error.to_string().contains("fragmented_control_frame"));
    }

    #[test]
    fn validate_rfc6455_rejects_reserved_opcode() {
        for opcode in [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
            let error = super::validate_websocket_frame_rfc6455(true, opcode)
                .expect_err(&format!("opcode {opcode:#x} must fail"));
            assert!(error.to_string().contains("reserved_opcode"));
        }
    }

    #[test]
    fn validate_rfc6455_accepts_valid_frames() {
        for opcode in [0x0, 0x1, 0x2] {
            super::validate_websocket_frame_rfc6455(true, opcode).expect("data frame should pass");
            super::validate_websocket_frame_rfc6455(false, opcode)
                .expect("continuation frame should pass");
        }
        for opcode in [0x8, 0x9, 0xA] {
            super::validate_websocket_frame_rfc6455(true, opcode)
                .expect("control frame with fin should pass");
        }
    }
}
