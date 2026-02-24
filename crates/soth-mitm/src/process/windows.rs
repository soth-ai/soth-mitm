use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tokio::process::Command;

use super::{ConnectionInfo, ProcessAttributor, ProcessInfo};

#[derive(Debug, Default)]
pub(crate) struct PlatformProcessAttributor;

impl ProcessAttributor for PlatformProcessAttributor {
    fn lookup<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        Box::pin(async move { lookup_process(connection).await })
    }
}

async fn lookup_process(connection: &ConnectionInfo) -> Option<ProcessInfo> {
    let pid = lookup_pid(connection).await?;
    let process_name = tasklist_name(pid)
        .await
        .unwrap_or_else(|| "unknown".to_string());
    let process_path = process_path(pid)
        .await
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&process_name));

    Some(ProcessInfo {
        pid,
        process_name,
        process_path,
        bundle_id: None,
        code_signature: None,
        parent_pid: None,
        parent_name: None,
    })
}

async fn lookup_pid(connection: &ConnectionInfo) -> Option<u32> {
    let output = Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_netstat_pid(&output.stdout, connection.source_port)
}

async fn tasklist_name(pid: u32) -> Option<String> {
    let filter = format!("PID eq {pid}");
    let output = Command::new("tasklist")
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_tasklist_name(&output.stdout)
}

async fn process_path(pid: u32) -> Option<String> {
    let filter = format!("processid={pid}");
    let output = Command::new("wmic")
        .args([
            "process",
            "where",
            &filter,
            "get",
            "ExecutablePath",
            "/value",
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_wmic_executable_path(&output.stdout)
}

fn parse_netstat_pid(raw: &[u8], source_port: u16) -> Option<u32> {
    let needle = format!(":{source_port}");
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if !line.contains("ESTABLISHED") || !line.contains(&needle) {
            continue;
        }
        let pid_token = line.split_whitespace().last()?;
        if let Ok(pid) = pid_token.parse::<u32>() {
            return Some(pid);
        }
    }
    None
}

fn parse_tasklist_name(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let line = text.lines().next()?.trim();
    if line.is_empty() || line.starts_with("INFO:") {
        return None;
    }
    let trimmed = line.trim_matches('"');
    trimmed.split("\",\"").next().map(str::to_string)
}

fn parse_wmic_executable_path(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("ExecutablePath=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_netstat_pid, parse_tasklist_name, parse_wmic_executable_path};

    #[test]
    fn parse_windows_pid_from_netstat() {
        let sample = b"  TCP    127.0.0.1:58231    127.0.0.1:8080    ESTABLISHED    19420\r\n";
        assert_eq!(parse_netstat_pid(sample, 58231), Some(19420));
    }

    #[test]
    fn parse_windows_tasklist_name() {
        let sample = br#""chrome.exe","19420","Console","1","123,456 K""#;
        assert_eq!(parse_tasklist_name(sample), Some("chrome.exe".to_string()));
    }

    #[test]
    fn parse_windows_wmic_path() {
        let sample = b"\r\nExecutablePath=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\r\n\r\n";
        assert_eq!(
            parse_wmic_executable_path(sample),
            Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string())
        );
    }
}
