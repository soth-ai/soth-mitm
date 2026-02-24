#![allow(dead_code)]

use std::fmt::Display;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub struct LatencySummary {
    pub samples: usize,
    pub min_us: u128,
    pub p50_us: u128,
    pub p95_us: u128,
    pub p99_us: u128,
    pub max_us: u128,
    pub mean_us: u128,
}

pub fn summarize_latency(samples: &[Duration]) -> LatencySummary {
    let mut micros: Vec<u128> = samples.iter().map(Duration::as_micros).collect();
    micros.sort_unstable();
    let samples_len = micros.len();
    if samples_len == 0 {
        return LatencySummary {
            samples: 0,
            min_us: 0,
            p50_us: 0,
            p95_us: 0,
            p99_us: 0,
            max_us: 0,
            mean_us: 0,
        };
    }

    let sum: u128 = micros.iter().copied().sum();
    LatencySummary {
        samples: samples_len,
        min_us: micros[0],
        p50_us: percentile_us(&micros, 50),
        p95_us: percentile_us(&micros, 95),
        p99_us: percentile_us(&micros, 99),
        max_us: micros[samples_len - 1],
        mean_us: sum / (samples_len as u128),
    }
}

fn percentile_us(sorted_micros: &[u128], percentile: usize) -> u128 {
    debug_assert!(!sorted_micros.is_empty());
    let n = sorted_micros.len();
    let rank = (percentile * n).div_ceil(100);
    let index = rank.saturating_sub(1).min(n - 1);
    sorted_micros[index]
}

pub fn parse_usize_arg(args: &[String], flag: &str, default: usize) -> Result<usize, io::Error> {
    for window in args.windows(2) {
        if window[0] == flag {
            return window[1].parse::<usize>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid value for {flag}: {error}"),
                )
            });
        }
    }
    Ok(default)
}

pub fn parse_u128_arg(args: &[String], flag: &str, default: u128) -> Result<u128, io::Error> {
    for window in args.windows(2) {
        if window[0] == flag {
            return window[1].parse::<u128>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid value for {flag}: {error}"),
                )
            });
        }
    }
    Ok(default)
}

pub fn parse_path_arg(args: &[String], flag: &str) -> Option<PathBuf> {
    for window in args.windows(2) {
        if window[0] == flag {
            return Some(PathBuf::from(&window[1]));
        }
    }
    None
}

pub fn write_result_file(path: Option<PathBuf>, kv_rows: &[(&str, String)]) -> io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut text = String::new();
    for (key, value) in kv_rows {
        text.push_str(key);
        text.push('\t');
        text.push_str(value);
        text.push('\n');
    }
    fs::write(path, text)
}

pub fn print_result_stdout(kv_rows: &[(&str, String)]) {
    for (key, value) in kv_rows {
        println!("{key}\t{value}");
    }
}

pub fn free_loopback_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

pub fn now_epoch_micros() -> io::Result<u128> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| io::Error::other(format!("clock drift before unix epoch: {error}")))?;
    Ok(elapsed.as_micros())
}

pub fn io_other(context: &str, error: impl Display) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}
