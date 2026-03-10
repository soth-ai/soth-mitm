#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub id: Option<String>,
    pub retry_ms: Option<u64>,
    pub data: String,
    pub data_line_count: usize,
}

#[derive(Debug, Default)]
pub struct SseParser {
    pending_line: Vec<u8>,
    data_lines: Vec<String>,
    event: Option<String>,
    id: Option<String>,
    retry_ms: Option<u64>,
    has_fields: bool,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let mut emitted = Vec::new();
        for byte in chunk {
            if *byte == b'\n' {
                self.process_completed_line(&mut emitted);
            } else {
                self.pending_line.push(*byte);
            }
        }
        emitted
    }

    pub fn finish(&mut self) -> Option<SseEvent> {
        if !self.pending_line.is_empty() {
            let mut line = std::mem::take(&mut self.pending_line);
            trim_trailing_carriage_return(&mut line);
            self.apply_line(&line);
        }
        self.dispatch_event()
    }

    fn process_completed_line(&mut self, emitted: &mut Vec<SseEvent>) {
        let mut line = std::mem::take(&mut self.pending_line);
        trim_trailing_carriage_return(&mut line);
        if line.is_empty() {
            if let Some(event) = self.dispatch_event() {
                emitted.push(event);
            }
            return;
        }
        self.apply_line(&line);
    }

    fn apply_line(&mut self, line: &[u8]) {
        if line.first() == Some(&b':') {
            return;
        }
        let (field_bytes, value_bytes) = parse_field_line(line);
        if field_bytes.is_empty() {
            return;
        }
        let field = String::from_utf8_lossy(field_bytes);
        let value = String::from_utf8_lossy(value_bytes).into_owned();
        match field.as_ref() {
            "data" => {
                self.data_lines.push(value);
                self.has_fields = true;
            }
            "event" => {
                self.event = Some(value);
                self.has_fields = true;
            }
            "id" => {
                if !value.contains('\0') {
                    self.id = Some(value);
                    self.has_fields = true;
                }
            }
            "retry" => {
                if let Ok(retry_ms) = value.parse::<u64>() {
                    self.retry_ms = Some(retry_ms);
                    self.has_fields = true;
                }
            }
            _ => {}
        }
    }

    fn dispatch_event(&mut self) -> Option<SseEvent> {
        if !self.has_fields
            && self.data_lines.is_empty()
            && self.event.is_none()
            && self.id.is_none()
            && self.retry_ms.is_none()
        {
            return None;
        }

        let data_line_count = self.data_lines.len();
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        self.has_fields = false;

        Some(SseEvent {
            event: self.event.take(),
            id: self.id.take(),
            retry_ms: self.retry_ms.take(),
            data,
            data_line_count,
        })
    }
}

fn trim_trailing_carriage_return(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
}

fn parse_field_line(line: &[u8]) -> (&[u8], &[u8]) {
    if let Some(separator_index) = line.iter().position(|byte| *byte == b':') {
        let field = &line[..separator_index];
        let mut value = &line[separator_index + 1..];
        if value.first() == Some(&b' ') {
            value = &value[1..];
        }
        (field, value)
    } else {
        (line, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::{SseEvent, SseParser};

    #[test]
    fn parses_event_id_retry_and_multiline_data_across_chunks() {
        let mut parser = SseParser::new();
        let first = parser.push_bytes(b"event: update\nid: abc\nretry: 1500\ndata: line-1\nd");
        assert!(first.is_empty());

        let second = parser.push_bytes(b"ata: line-2\n\n");
        assert_eq!(
            second,
            vec![SseEvent {
                event: Some("update".to_string()),
                id: Some("abc".to_string()),
                retry_ms: Some(1500),
                data: "line-1\nline-2".to_string(),
                data_line_count: 2,
            }]
        );
    }

    #[test]
    fn ignores_comments_and_invalid_retry_and_flushes_on_finish() {
        let mut parser = SseParser::new();
        let emitted = parser.push_bytes(b":comment\ndata: hello\nretry: bad");
        assert!(emitted.is_empty());

        let flushed = parser.finish().expect("must flush trailing event");
        assert_eq!(flushed.event, None);
        assert_eq!(flushed.id, None);
        assert_eq!(flushed.retry_ms, None);
        assert_eq!(flushed.data, "hello");
        assert_eq!(flushed.data_line_count, 1);
    }
}
