use std::fs;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mitm_http::ApplicationProtocol;
use mitm_observe::{
    deterministic_event_record_v2, Event, EventConsumer, EventEnvelope, EventLogV2Config,
    EventLogV2Consumer, EventType, FlowContext,
};

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn deterministic_record_v2_omits_runtime_clocks() {
    let context = sample_context(11);
    let mut first = Event::new(EventType::RequestHeaders, context.clone());
    first.sequence_id = 1;
    first.flow_sequence_id = 1;
    first.occurred_at_monotonic_ns = 7;
    first.occurred_at_unix_ms = 111;
    first
        .attributes
        .insert("method".to_string(), "GET".to_string());

    let mut second = first.clone();
    second.occurred_at_monotonic_ns = 999_999;
    second.occurred_at_unix_ms = 999_999;

    let first_record = deterministic_event_record_v2(&EventEnvelope::from_event(first));
    let second_record = deterministic_event_record_v2(&EventEnvelope::from_event(second));
    assert_eq!(first_record, second_record);
}

#[test]
fn deterministic_record_v2_uses_stream_aware_grpc_key() {
    let mut event = Event::new(EventType::GrpcResponseHeaders, sample_context(42));
    event.sequence_id = 3;
    event.flow_sequence_id = 8;
    event
        .attributes
        .insert("grpc_path".to_string(), "/pkg.Service/Call".to_string());
    event
        .attributes
        .insert("grpc_event_sequence".to_string(), "2".to_string());

    let record = deterministic_event_record_v2(&EventEnvelope::from_event(event));
    assert_eq!(record.stream_key, "grpc:/pkg.Service/Call:2");
    assert_eq!(record.kind, "grpc_response_headers");
    assert_eq!(record.protocol, "tunnel");
}

#[test]
fn event_log_v2_consumer_writes_index_and_rotates_segments() {
    let temp_dir = unique_temp_dir("event_log_v2_rotates");
    let log_path = temp_dir.join("events.jsonl");
    let config = EventLogV2Config::new(&log_path)
        .with_flush_every(1)
        .with_rotate_bytes(Some(240));

    let consumer = EventLogV2Consumer::new(config.clone()).expect("create consumer");

    for sequence_id in 1..=6 {
        let mut event = Event::new(EventType::WebSocketFrame, sample_context(77));
        event.sequence_id = sequence_id;
        event.flow_sequence_id = sequence_id;
        event
            .attributes
            .insert("sequence_no".to_string(), sequence_id.to_string());
        event
            .attributes
            .insert("payload".to_string(), "x".repeat(48));
        consumer.consume(EventEnvelope::from_event(event));
    }
    consumer.flush().expect("flush consumer");

    let index = fs::read_to_string(&config.index_path).expect("read index");
    let rows: Vec<&str> = index.lines().skip(1).collect();
    assert_eq!(rows.len(), 6);
    assert!(
        rows.iter().any(|row| row.split('\t').nth(6) == Some("1")),
        "at least one event must rotate into segment 1"
    );
    assert_eq!(consumer.write_error_count(), 0);
    assert!(consumer.last_error().is_none());

    drop(consumer);
    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

fn sample_context(flow_id: u64) -> FlowContext {
    FlowContext {
        flow_id,
        client_addr: "127.0.0.1:12345".to_string(),
        server_host: "example.com".to_string(),
        server_port: 443,
        protocol: ApplicationProtocol::Tunnel,
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_millis();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "soth_mitm_{prefix}_{}_{}_{}",
        process::id(),
        now_ms,
        counter
    ))
}
