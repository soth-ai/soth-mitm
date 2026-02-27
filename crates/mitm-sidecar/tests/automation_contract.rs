use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn sidecar_emits_machine_readable_exit_contract_for_sink_init_failures() {
    let temp_dir = unique_temp_dir("sidecar_exit_contract");
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let status_path = temp_dir.join("status.jsonl");
    let invalid_parent = temp_dir.join("sink_parent_file");
    fs::write(&invalid_parent, b"not_a_directory").expect("write invalid sink parent file");
    let invalid_sink_path = invalid_parent.join("events.jsonl");

    let mut command = sidecar_command();
    let output = run_command_with_timeout(
        command
            // Force event sink init failure portably: parent path is a regular file.
            .env("SOTH_MITM_EVENT_LOG_V2_PATH", &invalid_sink_path)
            .env("SOTH_MITM_AUTOMATION_STATUS_PATH", &status_path),
        Duration::from_secs(180),
    );

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
    command.env(
        "CARGO_TARGET_DIR",
        unique_temp_dir("sidecar_command_target"),
    );
    command
}

struct CapturedOutput {
    status: std::process::ExitStatus,
    stderr: Vec<u8>,
}

fn run_command_with_timeout(command: &mut Command, timeout: Duration) -> CapturedOutput {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn sidecar command");
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut stream) = child.stdout.take() {
                    stream.read_to_end(&mut stdout).expect("read child stdout");
                }
                if let Some(mut stream) = child.stderr.take() {
                    stream.read_to_end(&mut stderr).expect("read child stderr");
                }
                return CapturedOutput { status, stderr };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("sidecar command exceeded timeout of {:?}", timeout);
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("wait for sidecar command: {error}"),
        }
    }
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
