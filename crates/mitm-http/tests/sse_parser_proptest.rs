use mitm_http::SseParser;
use proptest::prelude::*;

fn line_strategy() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z0-9]{0,12}").expect("line regex")
}

proptest! {
    #[test]
    fn multiline_data_round_trips_under_arbitrary_split(
        lines in proptest::collection::vec(line_strategy(), 1..8),
        split in 0_usize..512,
    ) {
        let mut payload = String::new();
        for line in &lines {
            payload.push_str("data: ");
            payload.push_str(line);
            payload.push('\n');
        }
        payload.push('\n');

        let bytes = payload.as_bytes();
        let split_at = split.min(bytes.len());
        let mut parser = SseParser::new();

        let mut emitted = Vec::new();
        emitted.extend(parser.push_bytes(&bytes[..split_at]));
        emitted.extend(parser.push_bytes(&bytes[split_at..]));

        prop_assert_eq!(emitted.len(), 1);
        let event = &emitted[0];
        prop_assert_eq!(event.data_line_count, lines.len());
        prop_assert_eq!(event.data.as_str(), lines.join("\n"));
    }

    #[test]
    fn comment_only_input_emits_no_events(
        comments in proptest::collection::vec(line_strategy(), 1..8),
        split in 0_usize..512,
    ) {
        let mut payload = String::new();
        for comment in &comments {
            payload.push(':');
            payload.push_str(comment);
            payload.push('\n');
        }
        payload.push('\n');

        let bytes = payload.as_bytes();
        let split_at = split.min(bytes.len());
        let mut parser = SseParser::new();

        let mut emitted = Vec::new();
        emitted.extend(parser.push_bytes(&bytes[..split_at]));
        emitted.extend(parser.push_bytes(&bytes[split_at..]));
        let tail = parser.finish();

        prop_assert!(emitted.is_empty());
        prop_assert!(tail.is_none());
    }

    #[test]
    fn invalid_retry_field_does_not_set_retry_ms(
        bad_retry in proptest::string::string_regex("[a-zA-Z_-]{1,16}").expect("retry regex"),
        data_line in line_strategy(),
    ) {
        let payload = format!("retry: {bad_retry}\ndata: {data_line}\n\n");
        let mut parser = SseParser::new();
        let emitted = parser.push_bytes(payload.as_bytes());

        prop_assert_eq!(emitted.len(), 1);
        let event = &emitted[0];
        prop_assert_eq!(event.retry_ms, None);
        prop_assert_eq!(event.data.as_str(), data_line.as_str());
    }
}
