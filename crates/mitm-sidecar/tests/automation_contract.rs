use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn sidecar_emits_machine_readable_exit_contract_for_sink_init_failures() {
    let temp_dir = unique_temp_dir("sidecar_exit_contract");
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let status_path = temp_dir.join("status.jsonl");

    let mut command = sidecar_command();
    let output = command
        .env("SOTH_MITM_EVENT_LOG_V2_PATH", "/dev/null/events.jsonl")
        .env("SOTH_MITM_AUTOMATION_STATUS_PATH", &status_path)
        .output()
        .expect("run sidecar binary");

    assert_eq!(
        output.status.code(),
        Some(21),
        "event sink initialization failure should use deterministic exit code"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_exit = stderr
        .lines()
        .rev()
        .find(|line| line.starts_with("SOTH_MITM_STATUS\t") && line.contains("\"stage\":\"exit\""))
        .expect("stderr must include machine-readable exit status");
    let stderr_payload = stderr_exit
        .strip_prefix("SOTH_MITM_STATUS\t")
        .expect("prefix must be present");
    let stderr_json: Value = serde_json::from_str(stderr_payload).expect("parse stderr status");
    assert_eq!(stderr_json["schema"], "soth-mitm-automation-status-v1");
    assert_eq!(stderr_json["stage"], "exit");
    assert_eq!(stderr_json["outcome"], "error");
    assert_eq!(stderr_json["exit_code"], 21);
    assert_eq!(stderr_json["exit_class"], "event_sink_init_failed");

    let status_file = fs::read_to_string(&status_path).expect("status file must exist");
    let status_exit = status_file
        .lines()
        .rev()
        .find(|line| line.contains("\"stage\":\"exit\""))
        .expect("status file must include exit record");
    let status_json: Value = serde_json::from_str(status_exit).expect("parse status file line");
    assert_eq!(status_json["exit_code"], 21);
    assert_eq!(status_json["exit_class"], "event_sink_init_failed");
    assert_eq!(status_json["outcome"], "error");

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

fn sidecar_command() -> Command {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_mitm-sidecar")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_mitm_sidecar"))
    {
        return Command::new(path);
    }

    let mut command = Command::new("cargo");
    command.args(["run", "-p", "mitm-sidecar", "--quiet"]);
    command.current_dir(workspace_root());
    command
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve workspace root")
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_millis();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "soth_mitm_{prefix}_{}_{}_{}",
        std::process::id(),
        now_ms,
        counter
    ))
}
