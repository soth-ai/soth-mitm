use std::ffi::OsStr;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use sysinfo::{Pid, System};

use super::{
    socket_pid::lookup_established_tcp_pid, ConnectionInfo, ProcessAttributor, ProcessIdentity,
    ProcessInfo,
};

#[derive(Debug, Default)]
pub(crate) struct PlatformProcessAttributor;

impl ProcessAttributor for PlatformProcessAttributor {
    fn lookup<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        let connection = connection.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || lookup_process(&connection))
                .await
                .ok()
                .flatten()
        })
    }

    fn lookup_identity<'a>(
        &'a self,
        connection: &'a ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessIdentity>> + Send + 'a>> {
        let connection = connection.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || lookup_identity(&connection))
                .await
                .ok()
                .flatten()
        })
    }

    fn lookup_by_identity<'a>(
        &'a self,
        identity: &'a ProcessIdentity,
    ) -> Pin<Box<dyn Future<Output = Option<ProcessInfo>> + Send + 'a>> {
        let pid = identity.pid;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || lookup_process_by_pid(pid))
                .await
                .ok()
                .flatten()
        })
    }
}

fn lookup_process(connection: &ConnectionInfo) -> Option<ProcessInfo> {
    let pid = lookup_pid(connection)?;
    lookup_process_by_pid(pid)
}

fn lookup_identity(connection: &ConnectionInfo) -> Option<ProcessIdentity> {
    let pid = lookup_pid(connection)?;
    let start_token = process_snapshot(pid)?.start_token;
    Some(ProcessIdentity { pid, start_token })
}

fn lookup_process_by_pid(pid: u32) -> Option<ProcessInfo> {
    let snapshot = process_snapshot(pid)?;

    Some(ProcessInfo {
        pid,
        bundle_id: None,
        exe_name: snapshot.exe_name,
        exe_path: snapshot.exe_path,
        parent_pid: snapshot.parent_pid,
    })
}

fn lookup_pid(connection: &ConnectionInfo) -> Option<u32> {
    lookup_established_tcp_pid(connection)
}

#[derive(Debug)]
struct ProcessSnapshot {
    exe_name: Option<String>,
    exe_path: Option<PathBuf>,
    parent_pid: Option<u32>,
    start_token: String,
}

fn process_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let mut system = System::new_all();
    system.refresh_all();
    let process = system.process(Pid::from_u32(pid))?;

    let exe_name = normalize_text(process.name());
    let exe_path = process
        .exe()
        .map(|path| path.to_path_buf())
        .filter(|path| !path.as_os_str().is_empty());
    let parent_pid = process.parent().map(|parent| parent.as_u32());
    let start_token = build_start_token(process.start_time(), parent_pid);

    Some(ProcessSnapshot {
        exe_name,
        exe_path,
        parent_pid,
        start_token,
    })
}

fn build_start_token(start_time_secs: u64, parent_pid: Option<u32>) -> String {
    let parent = parent_pid
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!("st={start_time_secs}|ppid={parent}")
}

fn normalize_text(value: impl AsRef<OsStr>) -> Option<String> {
    let text = value.as_ref().to_string_lossy().trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}
