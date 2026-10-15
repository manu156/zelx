#![forbid(unsafe_code)]
use std::{fs, path::PathBuf};
#[derive(Clone, Debug)]
pub struct AppIdentity {
    pub pid: i32,
    pub comm: String,
    pub cgroup: String,
    pub exe: PathBuf,
}
impl AppIdentity {
    pub fn resolve(pid: i32) -> Self {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let comm = fs::read(base.join("comm"))
            .ok()
            .map(|mut bytes| {
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                String::from_utf8(bytes)
                    .unwrap_or_else(|e| format!("__bytes__:{}", crate::escaped(e.as_bytes())))
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "__unknown__".to_owned());
        let cgroup = fs::read_to_string(base.join("cgroup"))
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            })
            .unwrap_or_default();
        let exe = fs::read_link(base.join("exe")).unwrap_or_default();
        Self {
            pid,
            comm,
            cgroup,
            exe,
        }
    }
}
