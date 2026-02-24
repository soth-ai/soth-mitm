use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::Serialize;

use crate::{Event, EventConsumer, EventEnvelope};
use mitm_http::ApplicationProtocol;

pub const DETERMINISTIC_EVENT_LOG_V2_SCHEMA: &str = "soth-mitm-event-log-v2";
const INDEX_HEADER: &str = "sequence_id\tflow_id\tflow_sequence_id\tkind\tprotocol\tstream_key\tsegment_id\tbyte_offset\tline_bytes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLogV2Config {
    pub log_path: PathBuf,
    pub index_path: PathBuf,
    pub flush_every: usize,
    pub rotate_bytes: Option<u64>,
}

impl EventLogV2Config {
    pub fn new(log_path: impl Into<PathBuf>) -> Self {
        let log_path = log_path.into();
        Self {
            index_path: default_index_path(&log_path),
            log_path,
            flush_every: 1,
            rotate_bytes: None,
        }
    }

    pub fn with_index_path(mut self, index_path: impl Into<PathBuf>) -> Self {
        self.index_path = index_path.into();
        self
    }

    pub fn with_flush_every(mut self, flush_every: usize) -> Self {
        self.flush_every = flush_every.max(1);
        self
    }

    pub fn with_rotate_bytes(mut self, rotate_bytes: Option<u64>) -> Self {
        self.rotate_bytes = rotate_bytes.filter(|value| *value > 0);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeterministicEventRecordV2 {
    pub schema: &'static str,
    pub sequence_id: u64,
    pub flow_id: u64,
    pub flow_sequence_id: u64,
    pub kind: &'static str,
    pub protocol: &'static str,
    pub stream_key: String,
    pub client_addr: String,
    pub server_host: String,
    pub server_port: u16,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug)]
struct EventLogV2State {
    log_writer: BufWriter<File>,
    index_writer: BufWriter<File>,
    segment_id: u64,
    segment_path: PathBuf,
    segment_bytes: u64,
    events_since_flush: usize,
}

#[derive(Debug)]
pub struct EventLogV2Consumer {
    config: EventLogV2Config,
    state: Mutex<EventLogV2State>,
    write_error_count: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl EventLogV2Consumer {
    pub fn new(config: EventLogV2Config) -> io::Result<Self> {
        if config.log_path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "event log v2 path must not be empty",
            ));
        }
        if config.index_path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "event log v2 index path must not be empty",
            ));
        }

        let state = create_state(&config)?;
        Ok(Self {
            config,
            state: Mutex::new(state),
            write_error_count: AtomicU64::new(0),
            last_error: Mutex::new(None),
        })
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut state = self.state.lock().expect("lock poisoned");
        flush_writers(&mut state)
    }

    pub fn write_error_count(&self) -> u64 {
        self.write_error_count.load(Ordering::Relaxed)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().expect("lock poisoned").clone()
    }

    fn consume_envelope(&self, envelope: &EventEnvelope) -> io::Result<()> {
        let record = deterministic_event_record_v2(envelope);
        let mut line = serde_json::to_vec(&record)
            .map_err(|error| io::Error::other(format!("serialize event log v2 record: {error}")))?;
        line.push(b'\n');

        let mut state = self.state.lock().expect("lock poisoned");
        maybe_rotate_segment(&self.config, &mut state, line.len() as u64)?;
        let offset = state.segment_bytes;
        state.log_writer.write_all(&line)?;
        state.segment_bytes = state.segment_bytes.saturating_add(line.len() as u64);
        let segment_id = state.segment_id;

        writeln!(
            state.index_writer,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            record.sequence_id,
            record.flow_id,
            record.flow_sequence_id,
            record.kind,
            record.protocol,
            record.stream_key,
            segment_id,
            offset,
            line.len(),
        )?;

        state.events_since_flush = state.events_since_flush.saturating_add(1);
        if state.events_since_flush >= self.config.flush_every {
            flush_writers(&mut state)?;
            state.events_since_flush = 0;
        }
        Ok(())
    }
}

impl EventConsumer for EventLogV2Consumer {
    fn consume(&self, envelope: EventEnvelope) {
        if let Err(error) = self.consume_envelope(&envelope) {
            self.write_error_count.fetch_add(1, Ordering::Relaxed);
            *self.last_error.lock().expect("lock poisoned") = Some(error.to_string());
            eprintln!("event log v2 sink write failed: {error}");
        }
    }
}

pub fn deterministic_event_record_v2(envelope: &EventEnvelope) -> DeterministicEventRecordV2 {
    let event = &envelope.event;
    let context = &event.context;
    DeterministicEventRecordV2 {
        schema: DETERMINISTIC_EVENT_LOG_V2_SCHEMA,
        sequence_id: event.sequence_id,
        flow_id: context.flow_id,
        flow_sequence_id: event.flow_sequence_id,
        kind: event.kind.as_str(),
        protocol: protocol_label(context.protocol),
        stream_key: event_stream_key(event),
        client_addr: context.client_addr.clone(),
        server_host: context.server_host.clone(),
        server_port: context.server_port,
        attributes: event.attributes.clone(),
    }
}

fn create_state(config: &EventLogV2Config) -> io::Result<EventLogV2State> {
    ensure_parent_exists(&config.log_path)?;
    ensure_parent_exists(&config.index_path)?;

    let segment_path = segment_path(&config.log_path, 0);
    let mut index_writer = BufWriter::new(create_truncated_file(&config.index_path)?);
    writeln!(index_writer, "{INDEX_HEADER}")?;

    Ok(EventLogV2State {
        log_writer: BufWriter::new(create_truncated_file(&segment_path)?),
        index_writer,
        segment_id: 0,
        segment_path,
        segment_bytes: 0,
        events_since_flush: 0,
    })
}

fn flush_writers(state: &mut EventLogV2State) -> io::Result<()> {
    state.log_writer.flush()?;
    state.index_writer.flush()
}

fn maybe_rotate_segment(
    config: &EventLogV2Config,
    state: &mut EventLogV2State,
    next_line_len: u64,
) -> io::Result<()> {
    let Some(limit_bytes) = config.rotate_bytes else {
        return Ok(());
    };
    if state.segment_bytes == 0 {
        return Ok(());
    }
    if state.segment_bytes.saturating_add(next_line_len) <= limit_bytes {
        return Ok(());
    }

    state.log_writer.flush()?;
    state.segment_id = state.segment_id.saturating_add(1);
    state.segment_path = segment_path(&config.log_path, state.segment_id);
    state.log_writer = BufWriter::new(create_truncated_file(&state.segment_path)?);
    state.segment_bytes = 0;
    Ok(())
}

fn default_index_path(log_path: &Path) -> PathBuf {
    let mut file_name = match log_path.file_name() {
        Some(name) => name.to_os_string(),
        None => OsString::from("events.jsonl"),
    };
    file_name.push(".index.tsv");

    match log_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(file_name),
        _ => PathBuf::from(file_name),
    }
}

fn segment_path(log_path: &Path, segment_id: u64) -> PathBuf {
    if segment_id == 0 {
        return log_path.to_path_buf();
    }

    let mut file_name = match log_path.file_name() {
        Some(name) => name.to_os_string(),
        None => OsString::from("events.jsonl"),
    };
    file_name.push(format!(".part{segment_id:05}"));

    match log_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(file_name),
        _ => PathBuf::from(file_name),
    }
}

fn ensure_parent_exists(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn create_truncated_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
}

fn protocol_label(protocol: ApplicationProtocol) -> &'static str {
    match protocol {
        ApplicationProtocol::Http1 => "http1",
        ApplicationProtocol::Http2 => "http2",
        ApplicationProtocol::WebSocket => "websocket",
        ApplicationProtocol::Sse => "sse",
        ApplicationProtocol::StreamableHttp => "streamable_http",
        ApplicationProtocol::Tunnel => "tunnel",
    }
}

fn event_stream_key(event: &Event) -> String {
    if let Some(stream_id) = event.attributes.get("http2_stream_id") {
        return format!("h2:{stream_id}");
    }
    if let Some(turn_id) = event.attributes.get("turn_id") {
        return format!("ws_turn:{turn_id}");
    }
    if let Some(sequence_no) = event.attributes.get("sequence_no") {
        return format!("sequence:{sequence_no}");
    }
    if let Some(grpc_sequence) = event.attributes.get("grpc_event_sequence") {
        if let Some(path) = event.attributes.get("grpc_path") {
            return format!("grpc:{path}:{grpc_sequence}");
        }
        return format!("grpc:{grpc_sequence}");
    }
    format!("flow:{}:{}", event.context.flow_id, event.flow_sequence_id)
}
