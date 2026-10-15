#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

pub mod daemon;
pub mod db;
pub mod identity;
#[allow(unsafe_code)]
pub mod linux;
pub mod policy;
pub mod prompt;

pub const DEFAULT_DB: &str = "/var/lib/zelx/zelx.db";

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

pub fn escaped(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        if (32..127).contains(&byte) {
            text.push(byte as char);
        } else {
            write!(text, "\\x{byte:02x}").expect("writing to a String cannot fail");
        }
    }
    text
}
