use std::future::Future;
use std::path::Component;
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
    let process_command = ps_value(pid, "command").await?;
    let process_name = ps_value(pid, "comm").await?;
    let parent_pid = ps_value(pid, "ppid")
        .await
        .and_then(|value| value.parse::<u32>().ok());
    let parent_name = match parent_pid {
        Some(ppid) => ps_value(ppid, "comm").await,
        None => None,
    };

    let process_path = process_command
        .split_whitespace()
        .next()
        .filter(|value| value.starts_with('/'))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&process_name));
    let bundle_id = lookup_bundle_id(&process_path).await;

    Some(ProcessInfo {
        pid,
        process_name,
        process_path,
        bundle_id,
        code_signature: None,
        parent_pid,
        parent_name,
    })
}

async fn lookup_pid(connection: &ConnectionInfo) -> Option<u32> {
    let socket_filter = format!("{}:{}", connection.source_ip, connection.source_port);
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

async fn ps_value(pid: u32, field: &str) -> Option<String> {
    let pid = pid.to_string();
    let format = format!("{field}=");
    let output = Command::new("ps")
        .args(["-p", &pid, "-o", &format])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
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

async fn lookup_bundle_id(process_path: &PathBuf) -> Option<String> {
    let app_bundle_path = app_bundle_path(process_path)?;
    let info_plist = app_bundle_path.join("Contents/Info.plist");

    let output = Command::new("defaults")
        .args(["read"])
        .arg(info_plist)
        .arg("CFBundleIdentifier")
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
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

    use super::{app_bundle_path, parse_lsof_pid};

    #[test]
    fn parses_pid_from_lsof_machine_output() {
        let raw = b"p4242\np5242\n";
        assert_eq!(parse_lsof_pid(raw), Some(4242));
    }

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
