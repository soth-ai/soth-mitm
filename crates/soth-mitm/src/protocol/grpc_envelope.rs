#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcEnvelopeParserLimits {
    pub max_message_len: usize,
}

impl Default for GrpcEnvelopeParserLimits {
    fn default() -> Self {
        Self {
            max_message_len: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcEnvelopeMalformedCode {
    InvalidCompressedFlag,
    MessageTooLarge,
    TruncatedPrefix,
    LengthMismatch,
}

impl GrpcEnvelopeMalformedCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCompressedFlag => "invalid_compressed_flag",
            Self::MessageTooLarge => "message_too_large",
            Self::TruncatedPrefix => "truncated_prefix",
            Self::LengthMismatch => "length_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcEnvelopeFrame {
    pub sequence_no: u64,
    pub compressed: bool,
    pub message_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcEnvelopeMalformed {
    pub code: GrpcEnvelopeMalformedCode,
    pub frame_sequence_no: u64,
    pub declared_message_len: Option<usize>,
    pub observed_prefix_bytes: usize,
    pub remaining_body_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcEnvelopeRecord {
    Frame(GrpcEnvelopeFrame),
    Malformed(GrpcEnvelopeMalformed),
}

#[derive(Debug, Clone)]
enum ParseState {
    Header {
        bytes: [u8; 5],
        filled: usize,
    },
    Body {
        sequence_no: u64,
        compressed: bool,
        message_len: usize,
        remaining: usize,
    },
    Failed,
}

#[derive(Debug, Clone)]
pub struct GrpcEnvelopeParser {
    limits: GrpcEnvelopeParserLimits,
    state: ParseState,
    next_frame_sequence_no: u64,
    finished: bool,
}

impl Default for GrpcEnvelopeParser {
    fn default() -> Self {
        Self::new(GrpcEnvelopeParserLimits::default())
    }
}

impl GrpcEnvelopeParser {
    pub fn new(limits: GrpcEnvelopeParserLimits) -> Self {
        Self {
            limits,
            state: ParseState::Header {
                bytes: [0_u8; 5],
                filled: 0,
            },
            next_frame_sequence_no: 1,
            finished: false,
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<GrpcEnvelopeRecord> {
        if self.finished || matches!(self.state, ParseState::Failed) {
            return Vec::new();
        }

        let mut offset = 0_usize;
        let mut out = Vec::new();

        while offset < chunk.len() {
            let next = match self.state.clone() {
                ParseState::Header {
                    mut bytes,
                    mut filled,
                } => {
                    let need = 5_usize.saturating_sub(filled);
                    let take = need.min(chunk.len() - offset);
                    bytes[filled..filled + take].copy_from_slice(&chunk[offset..offset + take]);
                    filled += take;
                    offset += take;
                    if filled < 5 {
                        ParseState::Header { bytes, filled }
                    } else {
                        let sequence_no = self.next_sequence_no();
                        let message_len =
                            u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
                        match bytes[0] {
                            0 | 1 => {
                                let compressed = bytes[0] == 1;
                                if message_len > self.limits.max_message_len {
                                    out.push(GrpcEnvelopeRecord::Malformed(
                                        GrpcEnvelopeMalformed {
                                            code: GrpcEnvelopeMalformedCode::MessageTooLarge,
                                            frame_sequence_no: sequence_no,
                                            declared_message_len: Some(message_len),
                                            observed_prefix_bytes: 5,
                                            remaining_body_bytes: Some(message_len),
                                        },
                                    ));
                                    ParseState::Failed
                                } else if message_len == 0 {
                                    out.push(GrpcEnvelopeRecord::Frame(GrpcEnvelopeFrame {
                                        sequence_no,
                                        compressed,
                                        message_len,
                                    }));
                                    ParseState::Header {
                                        bytes: [0_u8; 5],
                                        filled: 0,
                                    }
                                } else {
                                    ParseState::Body {
                                        sequence_no,
                                        compressed,
                                        message_len,
                                        remaining: message_len,
                                    }
                                }
                            }
                            _ => {
                                out.push(GrpcEnvelopeRecord::Malformed(GrpcEnvelopeMalformed {
                                    code: GrpcEnvelopeMalformedCode::InvalidCompressedFlag,
                                    frame_sequence_no: sequence_no,
                                    declared_message_len: Some(message_len),
                                    observed_prefix_bytes: 5,
                                    remaining_body_bytes: None,
                                }));
                                ParseState::Failed
                            }
                        }
                    }
                }
                ParseState::Body {
                    sequence_no,
                    compressed,
                    message_len,
                    mut remaining,
                } => {
                    let take = remaining.min(chunk.len() - offset);
                    remaining -= take;
                    offset += take;
                    if remaining == 0 {
                        out.push(GrpcEnvelopeRecord::Frame(GrpcEnvelopeFrame {
                            sequence_no,
                            compressed,
                            message_len,
                        }));
                        ParseState::Header {
                            bytes: [0_u8; 5],
                            filled: 0,
                        }
                    } else {
                        ParseState::Body {
                            sequence_no,
                            compressed,
                            message_len,
                            remaining,
                        }
                    }
                }
                ParseState::Failed => ParseState::Failed,
            };
            self.state = next;
            if matches!(self.state, ParseState::Failed) {
                break;
            }
        }

        out
    }

    pub fn finish(&mut self) -> Option<GrpcEnvelopeMalformed> {
        if self.finished {
            return None;
        }
        self.finished = true;

        let malformed = match self.state {
            ParseState::Header { filled, .. } if filled > 0 => Some(GrpcEnvelopeMalformed {
                code: GrpcEnvelopeMalformedCode::TruncatedPrefix,
                frame_sequence_no: self.next_frame_sequence_no,
                declared_message_len: None,
                observed_prefix_bytes: filled,
                remaining_body_bytes: None,
            }),
            ParseState::Body {
                sequence_no,
                message_len,
                remaining,
                ..
            } => Some(GrpcEnvelopeMalformed {
                code: GrpcEnvelopeMalformedCode::LengthMismatch,
                frame_sequence_no: sequence_no,
                declared_message_len: Some(message_len),
                observed_prefix_bytes: 5,
                remaining_body_bytes: Some(remaining),
            }),
            _ => None,
        };
        if malformed.is_some() {
            self.state = ParseState::Failed;
        }
        malformed
    }

    fn next_sequence_no(&mut self) -> u64 {
        let current = self.next_frame_sequence_no;
        self.next_frame_sequence_no = self.next_frame_sequence_no.saturating_add(1);
        current
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GrpcEnvelopeMalformedCode, GrpcEnvelopeParser, GrpcEnvelopeParserLimits, GrpcEnvelopeRecord,
    };

    fn frame(compressed_flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(compressed_flag);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_frames_when_prefix_and_payload_split_across_chunks() {
        let mut parser = GrpcEnvelopeParser::default();
        let mut records = Vec::new();

        let payload = frame(0, b"hello");
        for chunk in payload.chunks(2) {
            records.extend(parser.push_chunk(chunk));
        }
        assert_eq!(records.len(), 1);
        let GrpcEnvelopeRecord::Frame(record) = &records[0] else {
            panic!("expected frame");
        };
        assert_eq!(record.sequence_no, 1);
        assert!(!record.compressed);
        assert_eq!(record.message_len, 5);
        assert!(parser.finish().is_none());
    }

    #[test]
    fn parses_multiple_frames_from_single_stream() {
        let mut parser = GrpcEnvelopeParser::default();
        let mut bytes = frame(0, b"one");
        bytes.extend_from_slice(&frame(1, b"two"));
        let records = parser.push_chunk(&bytes);
        assert_eq!(records.len(), 2);
        let GrpcEnvelopeRecord::Frame(first) = &records[0] else {
            panic!("expected first frame");
        };
        let GrpcEnvelopeRecord::Frame(second) = &records[1] else {
            panic!("expected second frame");
        };
        assert_eq!(first.sequence_no, 1);
        assert_eq!(first.message_len, 3);
        assert!(!first.compressed);
        assert_eq!(second.sequence_no, 2);
        assert_eq!(second.message_len, 3);
        assert!(second.compressed);
        assert!(parser.finish().is_none());
    }

    #[test]
    fn classifies_invalid_compressed_flag() {
        let mut parser = GrpcEnvelopeParser::default();
        let records = parser.push_chunk(&frame(2, b""));
        assert_eq!(records.len(), 1);
        let GrpcEnvelopeRecord::Malformed(malformed) = &records[0] else {
            panic!("expected malformed");
        };
        assert_eq!(
            malformed.code,
            GrpcEnvelopeMalformedCode::InvalidCompressedFlag
        );
        assert_eq!(malformed.frame_sequence_no, 1);
    }

    #[test]
    fn classifies_message_too_large() {
        let mut parser = GrpcEnvelopeParser::new(GrpcEnvelopeParserLimits { max_message_len: 4 });
        let records = parser.push_chunk(&frame(0, b"12345"));
        assert_eq!(records.len(), 1);
        let GrpcEnvelopeRecord::Malformed(malformed) = &records[0] else {
            panic!("expected malformed");
        };
        assert_eq!(malformed.code, GrpcEnvelopeMalformedCode::MessageTooLarge);
        assert_eq!(malformed.declared_message_len, Some(5));
        assert_eq!(malformed.remaining_body_bytes, Some(5));
    }

    #[test]
    fn classifies_truncated_prefix_on_finish() {
        let mut parser = GrpcEnvelopeParser::default();
        assert!(parser.push_chunk(&[0, 0, 0]).is_empty());
        let malformed = parser.finish().expect("expected malformed");
        assert_eq!(malformed.code, GrpcEnvelopeMalformedCode::TruncatedPrefix);
        assert_eq!(malformed.observed_prefix_bytes, 3);
    }

    #[test]
    fn classifies_length_mismatch_on_finish() {
        let mut parser = GrpcEnvelopeParser::default();
        let full = frame(0, b"abcd");
        let short = &full[..full.len() - 2];
        assert!(parser.push_chunk(short).is_empty());
        let malformed = parser.finish().expect("expected malformed");
        assert_eq!(malformed.code, GrpcEnvelopeMalformedCode::LengthMismatch);
        assert_eq!(malformed.declared_message_len, Some(4));
        assert_eq!(malformed.remaining_body_bytes, Some(2));
    }
}
