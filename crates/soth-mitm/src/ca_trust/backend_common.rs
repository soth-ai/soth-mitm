use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(test)]
use std::sync::Mutex;

use crate::CaError;
#[cfg(test)]
use crate::CertificateAuthority;

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct InMemoryTrustBackend {
    trusted_fingerprint: Mutex<Option<String>>,
}

#[cfg(test)]
impl InMemoryTrustBackend {
    pub(crate) fn install(&self, ca: &CertificateAuthority) -> Result<(), CaError> {
        let mut trusted = self
            .trusted_fingerprint
            .lock()
            .map_err(|_| lock_error("install"))?;
        if trusted.as_deref() == Some(ca.fingerprint.as_str()) {
            return Ok(());
        }
        *trusted = Some(ca.fingerprint.clone());
        Ok(())
    }

    pub(crate) fn uninstall(&self) -> Result<(), CaError> {
        let mut trusted = self
            .trusted_fingerprint
            .lock()
            .map_err(|_| lock_error("uninstall"))?;
        *trusted = None;
        Ok(())
    }

    pub(crate) fn is_trusted(&self, fingerprint: &str) -> Result<bool, CaError> {
        let trusted = self
            .trusted_fingerprint
            .lock()
            .map_err(|_| lock_error("is_trusted"))?;
        Ok(trusted.as_deref() == Some(fingerprint))
    }
}

#[cfg(test)]
fn lock_error(operation: &str) -> CaError {
    CaError::Io(io::Error::other(format!(
        "trust backend lock poisoned during {operation}"
    )))
}

#[derive(Debug)]
pub(crate) struct CommandOutcome {
    pub success: bool,
    pub stderr: String,
}

pub(crate) fn run_command<I, S>(
    operation: &str,
    program: &str,
    args: I,
) -> Result<CommandOutcome, CaError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program).args(args).output().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            return CaError::UnsupportedOperation(format!(
                "{operation}: command '{program}' not found"
            ));
        }
        if error.kind() == io::ErrorKind::PermissionDenied {
            return CaError::PermissionDenied {
                operation: operation.to_string(),
                detail: error.to_string(),
            };
        }
        CaError::Io(error)
    })?;

    Ok(CommandOutcome {
        success: output.status.success(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub(crate) fn write_staged_cert(namespace: &str, cert_pem: &[u8]) -> Result<PathBuf, CaError> {
    let path = staged_cert_path(namespace)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, cert_pem)?;
    Ok(path)
}

pub(crate) fn write_state(
    namespace: &str,
    fingerprint: &str,
    cert_path: &Path,
) -> Result<(), CaError> {
    let state_path = trust_state_path(namespace)?;
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = format!(
        "fingerprint={}\ncert_path={}\n",
        fingerprint,
        cert_path.display()
    );
    fs::write(state_path, body)?;
    Ok(())
}

pub(crate) fn read_state(namespace: &str) -> Result<Option<(String, PathBuf)>, CaError> {
    let state_path = trust_state_path(namespace)?;
    if !state_path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(state_path)?;
    let mut fingerprint = None;
    let mut cert_path = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("fingerprint=") {
            fingerprint = Some(value.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("cert_path=") {
            cert_path = Some(PathBuf::from(value));
        }
    }
    match (fingerprint, cert_path) {
        (Some(fingerprint), Some(cert_path)) => Ok(Some((fingerprint, cert_path))),
        _ => Ok(None),
    }
}

pub(crate) fn clear_state(namespace: &str) -> Result<(), CaError> {
    let state_path = trust_state_path(namespace)?;
    match fs::remove_file(state_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CaError::Io(error)),
    }
}

pub(crate) fn operation_error(operation: &str, detail: impl Into<String>) -> CaError {
    let detail = detail.into();
    if permission_denied_hint(&detail) {
        return CaError::PermissionDenied {
            operation: operation.to_string(),
            detail,
        };
    }
    CaError::OperationFailed(format!("{operation}: {detail}"))
}

fn permission_denied_hint(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("permission denied")
        || lower.contains("not permitted")
        || lower.contains("user interaction is not allowed")
        || lower.contains("access is denied")
}

fn staged_cert_path(namespace: &str) -> Result<PathBuf, CaError> {
    Ok(base_state_dir()?.join(namespace).join("ca.pem"))
}

fn trust_state_path(namespace: &str) -> Result<PathBuf, CaError> {
    Ok(base_state_dir()?.join(namespace).join("trust_state.txt"))
}

fn base_state_dir() -> Result<PathBuf, CaError> {
    if let Some(path) = std::env::var_os("SOTH_MITM_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".soth-mitm"));
    }

    Err(CaError::UnsupportedOperation(
        "unable to determine state directory (set SOTH_MITM_STATE_DIR)".to_string(),
    ))
}
