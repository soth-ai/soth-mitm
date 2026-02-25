use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tokio::process::Command;

use super::{ConnectionInfo, ProcessAttributor, ProcessIdentity, ProcessInfo};
use crate::types::SocketFamily;

#[derive(Debug, Default)]
pub(crate) struct PlatformProcessAttributor;

impl ProcessAttributor for PlatformProcessAttributor {
    fn lookup<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        Box::pin(async move { lookup_process(connection).await })
    }

    fn lookup_identity<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessIdentity>> + Send + 'a>> {
        Box::pin(async move { lookup_identity(connection).await })
    }

    fn lookup_by_identity<'a>(
        &'a self,
        identity: &'a ProcessIdentity,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        Box::pin(async move { lookup_process_by_pid(identity.pid) })
    }
}

async fn lookup_process(connection: &ConnectionInfo) -> Option<ProcessInfo> {
    let pid = lookup_pid(connection).await?;
    lookup_process_by_pid(pid)
}

async fn lookup_identity(connection: &ConnectionInfo) -> Option<ProcessIdentity> {
    let pid = lookup_pid(connection).await?;
    let start_token = read_process_start_token(pid)?;
    Some(ProcessIdentity { pid, start_token })
}

fn lookup_process_by_pid(pid: u32) -> Option<ProcessInfo> {
    let process_name = read_process_name(pid);
    let process_path = read_process_path(pid);
    let parent_pid = read_parent_pid(pid);

    Some(ProcessInfo {
        pid,
        bundle_id: None,
        exe_name: process_name,
        exe_path: process_path,
        parent_pid,
    })
}

async fn lookup_pid(connection: &ConnectionInfo) -> Option<u32> {
    let socket_filter = match &connection.socket_family {
        SocketFamily::TcpV4 { local, .. } => format!("{}:{}", local.ip(), local.port()),
        SocketFamily::TcpV6 { local, .. } => format!("[{}]:{}", local.ip(), local.port()),
        SocketFamily::UnixDomain { .. } => return None,
    };
    let output = Command::new("lsof")
        .args([
            "-nP",
            "-iTCP",
            &socket_filter,
            "-sTCP:ESTABLISHED",
            "-F",
            "p",
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_lsof_pid(&output.stdout)
}

fn read_process_name(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    let name = std::fs::read_to_string(path).ok()?;
    let name = name.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn read_process_path(pid: u32) -> Option<PathBuf> {
    let path = format!("/proc/{pid}/exe");
    std::fs::read_link(path).ok()
}

fn read_parent_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(raw) = line.strip_prefix("PPid:") {
            return raw.trim().parse::<u32>().ok();
        }
    }
    None
}

fn read_process_start_token(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_start_time(&stat).map(|value| value.to_string())
}

fn parse_proc_start_time(stat: &str) -> Option<u64> {
    let (_, rest) = stat.split_once(") ")?;
    rest.split_whitespace().nth(19)?.parse::<u64>().ok()
}

fn parse_lsof_pid(raw: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if let Some(pid) = line.strip_prefix('p') {
            if let Ok(value) = pid.trim().parse::<u32>() {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_lsof_pid, parse_proc_start_time};

    #[test]
    fn parses_pid_from_lsof_machine_output() {
        let raw = b"p111\nf42\n";
        assert_eq!(parse_lsof_pid(raw), Some(111));
    }

    #[test]
    fn parses_linux_proc_start_time_field() {
        let sample = "111 (curl) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654321";
        assert_eq!(parse_proc_start_time(sample), Some(987654321));
    }
}
