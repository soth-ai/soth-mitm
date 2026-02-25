use mitm_http::{
    AntiHijackSanitizationStage, DecoderFrame, DecoderStage, DecoderStageProcessor,
    DecoderStageStatus, LayeredDecoderPipeline, SANITIZED_ATTRIBUTE, SANITIZED_PREFIX_ATTRIBUTE,
    SANITIZED_PROVENANCE_ATTRIBUTE,
};
use std::collections::BTreeMap;

fn run_payload_stage(input: &[u8]) -> mitm_http::DecoderPipelineResult {
    let mut processors: BTreeMap<DecoderStage, Box<dyn DecoderStageProcessor>> = BTreeMap::new();
    processors.insert(
        DecoderStage::PayloadParse,
        Box::new(AntiHijackSanitizationStage::default()),
    );
    let mut pipeline = LayeredDecoderPipeline::new(vec![DecoderStage::PayloadParse], processors)
        .expect("pipeline");
    pipeline.execute(DecoderFrame::new(input.to_vec(), true))
}

#[test]
fn anti_hijack_fixtures_parse_successfully_with_metadata() {
    let cases = [
        (
            include_bytes!("fixtures/anti_hijack/angular_guard.json").as_slice(),
            true,
            &["xssi_angular_prefix_lf", "xssi_angular_prefix_crlf"][..],
        ),
        (
            include_bytes!("fixtures/anti_hijack/while_guard.json").as_slice(),
            true,
            &["while_1_prefix"][..],
        ),
        (
            include_bytes!("fixtures/anti_hijack/plain.json").as_slice(),
            false,
            &[][..],
        ),
    ];

    for (fixture, expect_sanitized, expected_prefixes) in cases {
        let result = run_payload_stage(fixture);
        assert!(result.failure.is_none());
        assert_eq!(result.reports.len(), 1);
        assert_eq!(result.reports[0].status, DecoderStageStatus::Applied);

        parse_json_document(&result.output.bytes).expect("sanitized payload should parse");
        assert_eq!(
            result
                .output
                .attributes
                .get(SANITIZED_ATTRIBUTE)
                .map(String::as_str),
            Some(if expect_sanitized { "true" } else { "false" })
        );

        let prefix_attr = result
            .output
            .attributes
            .get(SANITIZED_PREFIX_ATTRIBUTE)
            .map(String::as_str);

        if expected_prefixes.is_empty() {
            assert_eq!(prefix_attr, None);
            assert!(!result
                .output
                .attributes
                .contains_key(SANITIZED_PROVENANCE_ATTRIBUTE));
            continue;
        }

        let observed_prefix = prefix_attr.expect("expected anti-hijack prefix metadata");
        assert!(
            expected_prefixes.contains(&observed_prefix),
            "unexpected anti-hijack prefix: {observed_prefix}"
        );
        let expected_provenance = format!("anti_hijack_prefix:{observed_prefix}");
        assert_eq!(
            result
                .output
                .attributes
                .get(SANITIZED_PROVENANCE_ATTRIBUTE)
                .map(String::as_str),
            Some(expected_provenance.as_str())
        );
    }
}

fn parse_json_document(input: &[u8]) -> Result<(), String> {
    let mut cursor = JsonCursor { input, offset: 0 };
    cursor.skip_whitespace();
    cursor.parse_value()?;
    cursor.skip_whitespace();
    if cursor.offset != input.len() {
        return Err(format!(
            "expected end of document, found trailing bytes at {}",
            cursor.offset
        ));
    }
    Ok(())
}

struct JsonCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl JsonCursor<'_> {
    fn parse_value(&mut self) -> Result<(), String> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string(),
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.parse_number(),
            Some(byte) => Err(format!("unexpected value byte {byte} at {}", self.offset)),
            None => Err("unexpected end of input while parsing value".to_string()),
        }
    }

    fn parse_object(&mut self) -> Result<(), String> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        if self.consume_if(b'}') {
            return Ok(());
        }

        loop {
            self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            self.parse_value()?;
            self.skip_whitespace();
            if self.consume_if(b',') {
                self.skip_whitespace();
                continue;
            }
            self.expect_byte(b'}')?;
            return Ok(());
        }
    }

    fn parse_array(&mut self) -> Result<(), String> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        if self.consume_if(b']') {
            return Ok(());
        }

        loop {
            self.parse_value()?;
            self.skip_whitespace();
            if self.consume_if(b',') {
                self.skip_whitespace();
                continue;
            }
            self.expect_byte(b']')?;
            return Ok(());
        }
    }

    fn parse_string(&mut self) -> Result<(), String> {
        self.expect_byte(b'"')?;
        loop {
            let Some(byte) = self.bump() else {
                return Err("unexpected end of input in string".to_string());
            };
            match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    let Some(escaped) = self.bump() else {
                        return Err("unexpected end of input after escape".to_string());
                    };
                    match escaped {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let Some(hex) = self.bump() else {
                                    return Err(
                                        "unexpected end of input in unicode escape".to_string()
                                    );
                                };
                                if !hex.is_ascii_hexdigit() {
                                    return Err(format!(
                                        "invalid unicode escape byte {hex} at {}",
                                        self.offset
                                    ));
                                }
                            }
                        }
                        _ => {
                            return Err(format!(
                                "invalid escape byte {escaped} at {}",
                                self.offset
                            ));
                        }
                    }
                }
                value if value < 0x20 => {
                    return Err(format!(
                        "control byte {} not allowed in string at {}",
                        value, self.offset
                    ));
                }
                _ => {}
            }
        }
    }

    fn parse_number(&mut self) -> Result<(), String> {
        self.consume_if(b'-');
        if self.consume_if(b'0') {
            if matches!(self.peek(), Some(next) if next.is_ascii_digit()) {
                return Err(format!("leading zero not allowed at {}", self.offset));
            }
        } else {
            self.consume_digits()?;
        }

        if self.consume_if(b'.') {
            self.consume_digits()?;
        }

        if self.consume_if(b'e') || self.consume_if(b'E') {
            self.consume_if(b'+');
            self.consume_if(b'-');
            self.consume_digits()?;
        }

        Ok(())
    }

    fn consume_digits(&mut self) -> Result<(), String> {
        let start = self.offset;
        while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
            self.offset += 1;
        }
        if self.offset == start {
            return Err(format!("expected digits at {}", self.offset));
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        for byte in literal {
            self.expect_byte(*byte)?;
        }
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        match self.bump() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(format!(
                "expected byte {expected}, found {actual} at {}",
                self.offset
            )),
            None => Err(format!(
                "expected byte {expected}, found end of input at {}",
                self.offset
            )),
        }
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(byte) if byte.is_ascii_whitespace()) {
            self.offset += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }
}
