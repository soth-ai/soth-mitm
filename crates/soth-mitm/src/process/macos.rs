use std::ffi::{c_void, OsStr};
use std::future::Future;
use std::mem;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::path::Component;
use std::path::PathBuf;
use std::pin::Pin;

use libc::{c_int, gid_t, uid_t, MAXCOMLEN};
use plist::Value;

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
    let bsd_info = read_bsd_info(pid)?;
    let exe_path = read_process_path(pid);
    let parent_pid = NonZeroU32::new(bsd_info.pbi_ppid).map(NonZeroU32::get);
    let path_name = exe_path.as_ref().and_then(process_name_from_path);
    let exe_name = super::derive_identity_walking_parents(
        pid,
        path_name.as_deref(),
        &read_process_args,
        &|p| {
            read_bsd_info(p)
                .and_then(|info| NonZeroU32::new(info.pbi_ppid))
                .map(NonZeroU32::get)
        },
    )
    .or(path_name)
    .or_else(|| process_name_from_bsd_info(&bsd_info));
    let start_token = build_start_token(bsd_info.pbi_start_tvsec, parent_pid);

    Some(ProcessSnapshot {
        exe_name,
        exe_path,
        parent_pid,
        start_token,
    })
}

fn read_bsd_info(pid: u32) -> Option<ProcBsdInfo> {
    let mut info = ProcBsdInfo::default();
    // SAFETY: `info` is a properly aligned writable buffer for `proc_pidinfo`.
    let written = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut ProcBsdInfo).cast::<c_void>(),
            mem::size_of::<ProcBsdInfo>() as c_int,
        )
    };
    if written as usize != mem::size_of::<ProcBsdInfo>() {
        return None;
    }
    if info.pbi_pid != pid {
        return None;
    }
    Some(info)
}

fn read_process_path(pid: u32) -> Option<PathBuf> {
    let mut raw = [0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: `raw` is a writable byte buffer accepted by `proc_pidpath`.
    let written = unsafe { proc_pidpath(pid as c_int, raw.as_mut_ptr().cast(), raw.len() as u32) };
    if written <= 0 {
        return None;
    }
    let written = (written as usize).min(raw.len());
    let bytes = bytes_before_nul(&raw[..written]);
    if bytes.is_empty() {
        return None;
    }
    let path = PathBuf::from(OsStr::from_bytes(bytes));
    if path.as_os_str().is_empty() {
        None
    } else {
        Some(path)
    }
}

fn read_process_args(pid: u32) -> Option<Vec<String>> {
    use libc::{c_int, c_void, CTL_KERN};

    const KERN_PROCARGS2: c_int = 49;

    let mut mib = [CTL_KERN, KERN_PROCARGS2, pid as c_int];

    let mut size: usize = 0;
    // SAFETY: querying the required buffer size for KERN_PROCARGS2.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }

    let mut buf = vec![0u8; size];
    // SAFETY: `buf` is a writable buffer of the declared size.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast::<c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    buf.truncate(size);

    if buf.len() < mem::size_of::<c_int>() {
        return None;
    }

    let argc = c_int::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    if argc == 0 {
        return None;
    }

    let rest = &buf[4..];

    // Skip the exec_path (null-terminated)
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut pos = exec_end + 1;

    // Skip null padding after exec_path
    while pos < rest.len() && rest[pos] == 0 {
        pos += 1;
    }

    // Read argv entries
    let mut args = Vec::with_capacity(argc.min(16));
    for _ in 0..argc {
        if pos >= rest.len() {
            break;
        }
        let end = rest[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| pos + i)
            .unwrap_or(rest.len());
        if let Ok(s) = std::str::from_utf8(&rest[pos..end]) {
            args.push(s.to_string());
        }
        pos = end + 1;
    }

    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

fn bytes_before_nul(raw: &[u8]) -> &[u8] {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    &raw[..end]
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

fn process_name_from_bsd_info(info: &ProcBsdInfo) -> Option<String> {
    c_char_array_to_string(&info.pbi_name).or_else(|| c_char_array_to_string(&info.pbi_comm))
}

fn process_name_from_path(path: &PathBuf) -> Option<String> {
    path.file_name().and_then(normalize_text)
}

fn c_char_array_to_string<const N: usize>(raw: &[i8; N]) -> Option<String> {
    let end = raw.iter().position(|ch| *ch == 0).unwrap_or(N);
    if end == 0 {
        return None;
    }
    let bytes = raw[..end]
        .iter()
        .map(|value| *value as u8)
        .collect::<Vec<u8>>();
    normalize_text(OsStr::from_bytes(&bytes))
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

const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: uid_t,
    pbi_gid: gid_t,
    pbi_ruid: uid_t,
    pbi_rgid: gid_t,
    pbi_svuid: uid_t,
    pbi_svgid: gid_t,
    rfu_1: u32,
    pbi_comm: [i8; MAXCOMLEN as usize],
    pbi_name: [i8; (2 * MAXCOMLEN) as usize],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

impl Default for ProcBsdInfo {
    fn default() -> Self {
        Self {
            pbi_flags: 0,
            pbi_status: 0,
            pbi_xstatus: 0,
            pbi_pid: 0,
            pbi_ppid: 0,
            pbi_uid: 0,
            pbi_gid: 0,
            pbi_ruid: 0,
            pbi_rgid: 0,
            pbi_svuid: 0,
            pbi_svgid: 0,
            rfu_1: 0,
            pbi_comm: [0; MAXCOMLEN as usize],
            pbi_name: [0; (2 * MAXCOMLEN) as usize],
            pbi_nfiles: 0,
            pbi_pgid: 0,
            pbi_pjobc: 0,
            e_tdev: 0,
            e_tpgid: 0,
            pbi_nice: 0,
            pbi_start_tvsec: 0,
            pbi_start_tvusec: 0,
        }
    }
}

unsafe extern "C" {
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        app_bundle_path, build_start_token, c_char_array_to_string, process_name_from_bsd_info,
        process_name_from_path, ProcBsdInfo,
    };

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

    #[test]
    fn parses_c_char_array_process_name() {
        let mut raw = [0i8; 8];
        raw[0] = b'c' as i8;
        raw[1] = b'u' as i8;
        raw[2] = b'r' as i8;
        raw[3] = b'l' as i8;
        assert_eq!(c_char_array_to_string(&raw), Some("curl".to_string()));
    }

    #[test]
    fn derives_process_name_from_path_filename() {
        let path = PathBuf::from("/Applications/Example.app/Contents/MacOS/example-bin");
        assert_eq!(
            process_name_from_path(&path),
            Some("example-bin".to_string())
        );
    }

    #[test]
    fn falls_back_to_comm_when_name_missing() {
        let mut info = ProcBsdInfo::default();
        info.pbi_comm[0] = b'b' as i8;
        info.pbi_comm[1] = b'a' as i8;
        info.pbi_comm[2] = b's' as i8;
        info.pbi_comm[3] = b'h' as i8;
        assert_eq!(process_name_from_bsd_info(&info), Some("bash".to_string()));
    }

    #[test]
    fn start_token_uses_parent_placeholder_for_missing_parent() {
        assert_eq!(build_start_token(123, None), "st=123|ppid=-");
    }
}
