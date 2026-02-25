use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use mitm_core::{MitmConfig, MitmEngine};
use mitm_observe::{EventConsumer, EventLogV2Config, EventLogV2Consumer, NoopEventConsumer};
use mitm_policy::DefaultPolicyEngine;
use mitm_sidecar::{SidecarConfig, SidecarServer};
use serde::Serialize;

const STATUS_SCHEMA: &str = "soth-mitm-automation-status-v1";
const STATUS_PREFIX: &str = "SOTH_MITM_STATUS\t";

const ENV_STATUS_PATH: &str = "SOTH_MITM_AUTOMATION_STATUS_PATH";
const ENV_EVENT_LOG_PATH: &str = "SOTH_MITM_EVENT_LOG_V2_PATH";
const ENV_EVENT_LOG_FLUSH_EVERY: &str = "SOTH_MITM_EVENT_LOG_V2_FLUSH_EVERY";
const ENV_EVENT_LOG_ROTATE_BYTES: &str = "SOTH_MITM_EVENT_LOG_V2_ROTATE_BYTES";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitClass {
    Ok,
    ConfigInvalid,
    EventSinkInitFailed,
    SidecarInitFailed,
    RuntimeFailed,
}

impl ExitClass {
    fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::ConfigInvalid => 20,
            Self::EventSinkInitFailed => 21,
            Self::SidecarInitFailed => 22,
            Self::RuntimeFailed => 23,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ConfigInvalid => "config_invalid",
            Self::EventSinkInitFailed => "event_sink_init_failed",
            Self::SidecarInitFailed => "sidecar_init_failed",
            Self::RuntimeFailed => "runtime_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunOutcome {
    class: ExitClass,
    detail: Option<String>,
}

impl RunOutcome {
    fn ok(detail: Option<String>) -> Self {
        Self {
            class: ExitClass::Ok,
            detail,
        }
    }

    fn error(class: ExitClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: Some(detail.into()),
        }
    }

    fn exit_code(&self) -> i32 {
        self.class.code()
    }

    fn status_record(&self) -> StatusRecord {
        StatusRecord::new(
            "exit",
            if self.class == ExitClass::Ok {
                "ok"
            } else {
                "error"
            },
            self.exit_code(),
            self.class.label(),
            self.detail.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StatusRecord {
    schema: &'static str,
    stage: &'static str,
    outcome: &'static str,
    exit_code: i32,
    exit_class: &'static str,
    unix_ms: u128,
    detail: Option<String>,
}

impl StatusRecord {
    fn new(
        stage: &'static str,
        outcome: &'static str,
        exit_code: i32,
        exit_class: &'static str,
        detail: Option<String>,
    ) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            stage,
            outcome,
            exit_code,
            exit_class,
            unix_ms: now_unix_ms(),
            detail,
        }
    }
}

#[derive(Debug, Default)]
struct StatusEmitter {
    status_file: Option<Mutex<BufWriter<File>>>,
}

impl StatusEmitter {
    fn from_env() -> Self {
        let path = env::var(ENV_STATUS_PATH)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let Some(path) = path else {
            return Self::default();
        };

        let status_file = match open_status_file(&path) {
            Ok(file) => Some(Mutex::new(BufWriter::new(file))),
            Err(error) => {
                eprintln!("failed to open status stream file {path}: {error}");
                None
            }
        };
        Self { status_file }
    }

    fn emit(&self, record: StatusRecord) {
        let json = match serde_json::to_string(&record) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("failed to serialize status record: {error}");
                return;
            }
        };

        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "{STATUS_PREFIX}{json}");
        let _ = stderr.flush();

        if let Some(status_file) = self.status_file.as_ref() {
            let mut writer = status_file.lock().expect("lock poisoned");
            let _ = writeln!(writer, "{json}");
            let _ = writer.flush();
        }
    }
}

#[tokio::main]
async fn main() {
    let status_emitter = StatusEmitter::from_env();
    status_emitter.emit(StatusRecord::new(
        "startup",
        "in_progress",
        0,
        "ok",
        Some("bootstrapping sidecar".to_string()),
    ));

    let outcome = run_sidecar(&status_emitter).await;
    status_emitter.emit(outcome.status_record());
    std::process::exit(outcome.exit_code());
}

async fn run_sidecar(status_emitter: &StatusEmitter) -> RunOutcome {
    let mitm_config = MitmConfig::default();
    let sink = match build_event_sink_from_env() {
        Ok(sink) => sink,
        Err(error) => return RunOutcome::error(ExitClass::EventSinkInitFailed, error.to_string()),
    };

    let policy = DefaultPolicyEngine::new(
        mitm_config.ignore_hosts.clone(),
        mitm_config.blocked_hosts.clone(),
    );
    let engine = match MitmEngine::new_checked(mitm_config.clone(), policy, sink) {
        Ok(engine) => engine,
        Err(error) => return RunOutcome::error(ExitClass::ConfigInvalid, error.to_string()),
    };

    let sidecar_config = SidecarConfig {
        listen_addr: mitm_config.listen_addr,
        listen_port: mitm_config.listen_port,
        max_connect_head_bytes: 64 * 1024,
        max_http_head_bytes: mitm_config.max_http_head_bytes,
        idle_watchdog_timeout: std::time::Duration::from_secs(30),
        stream_stage_timeout: std::time::Duration::from_secs(15),
        unix_socket_path: None,
    };

    status_emitter.emit(StatusRecord::new(
        "running",
        "ready",
        0,
        "ok",
        Some(format!(
            "listening on {}:{}",
            sidecar_config.listen_addr, sidecar_config.listen_port
        )),
    ));

    let server = match SidecarServer::new(sidecar_config, engine) {
        Ok(server) => server,
        Err(error) => return RunOutcome::error(ExitClass::SidecarInitFailed, error.to_string()),
    };

    match server.run().await {
        Ok(()) => RunOutcome::ok(Some("server exited cleanly".to_string())),
        Err(error) => RunOutcome::error(ExitClass::RuntimeFailed, error.to_string()),
    }
}

fn build_event_sink_from_env() -> io::Result<Box<dyn EventConsumer + Send + Sync>> {
    let path = env::var(ENV_EVENT_LOG_PATH)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(path) = path else {
        return Ok(Box::new(NoopEventConsumer));
    };

    let flush_every = parse_nonzero_usize_from_env(ENV_EVENT_LOG_FLUSH_EVERY, 1)?;
    let rotate_bytes = parse_optional_nonzero_u64_from_env(ENV_EVENT_LOG_ROTATE_BYTES)?;
    let consumer = EventLogV2Consumer::new(
        EventLogV2Config::new(path)
            .with_flush_every(flush_every)
            .with_rotate_bytes(rotate_bytes),
    )?;
    Ok(Box::new(consumer))
}

fn parse_nonzero_usize_from_env(name: &str, default: usize) -> io::Result<usize> {
    let value = match env::var(name) {
        Ok(raw) => raw.trim().to_string(),
        Err(env::VarError::NotPresent) => return Ok(default),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be valid UTF-8"),
            ))
        }
    };
    if value.is_empty() {
        return Ok(default);
    }
    let parsed = value.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a positive integer: {error}"),
        )
    })?;
    if parsed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be greater than zero"),
        ));
    }
    Ok(parsed)
}

fn parse_optional_nonzero_u64_from_env(name: &str) -> io::Result<Option<u64>> {
    let value = match env::var(name) {
        Ok(raw) => raw.trim().to_string(),
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be valid UTF-8"),
            ))
        }
    };
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value.parse::<u64>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a positive integer: {error}"),
        )
    })?;
    if parsed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be greater than zero"),
        ));
    }
    Ok(Some(parsed))
}

fn open_status_file(path: &str) -> io::Result<File> {
    let path = std::path::Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}

fn now_unix_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}
