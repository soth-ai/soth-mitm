use std::ffi::OsStr;
use std::future::Future;
use std::path::Component;
use std::path::PathBuf;
use std::pin::Pin;

use plist::Value;
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
    let start_token = process_start_token(pid)?;
    Some(ProcessIdentity { pid, start_token })
}

fn lookup_process_by_pid(pid: u32) -> Option<ProcessInfo> {
    let snapshot = process_snapshot(pid)?;
    let bundle_id = snapshot.exe_path.as_ref().and_then(lookup_bundle_id);

    Some(ProcessInfo {
        pid,
        exe_name: snapshot.exe_name,
        exe_path: snapshot.exe_path,
        bundle_id,
        parent_pid: snapshot.parent_pid,
    })
}

fn lookup_pid(connection: &ConnectionInfo) -> Option<u32> {
    lookup_established_tcp_pid(connection)
}

fn process_start_token(pid: u32) -> Option<String> {
    process_snapshot(pid).map(|snapshot| snapshot.start_token)
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

fn lookup_bundle_id(process_path: &PathBuf) -> Option<String> {
    let app_bundle_path = app_bundle_path(process_path)?;
    let info_plist = app_bundle_path.join("Contents").join("Info.plist");

    let plist = Value::from_file(info_plist).ok()?;
    let dict = plist.as_dictionary()?;
    let bundle_id = dict.get("CFBundleIdentifier")?.as_string()?.trim();
    if bundle_id.is_empty() {
        None
    } else {
        Some(bundle_id.to_string())
    }
}

fn app_bundle_path(process_path: &PathBuf) -> Option<PathBuf> {
    let mut bundle = PathBuf::new();
    for component in process_path.components() {
        match component {
            Component::RootDir => bundle.push(component.as_os_str()),
            _ => bundle.push(component.as_os_str()),
        }
        if component.as_os_str().to_string_lossy().ends_with(".app") {
            return Some(bundle);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::app_bundle_path;

    #[test]
    fn extracts_app_bundle_path_from_binary_path() {
        let path = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        assert_eq!(
            app_bundle_path(&path),
            Some(PathBuf::from("/Applications/Google Chrome.app"))
        );
    }

    #[test]
    fn returns_none_for_non_bundle_path() {
        let path = PathBuf::from("/usr/bin/curl");
        assert!(app_bundle_path(&path).is_none());
    }
}
