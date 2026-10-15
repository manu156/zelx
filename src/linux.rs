//! Linux ABI boundary. All production unsafe code belongs in this module.
use anyhow::{bail, Context, Result};
use std::{
    ffi::{CString, OsString},
    fs::{self, File},
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments and cannot invalidate Rust memory.
    unsafe { libc::geteuid() }
}
pub fn private_umask() {
    // SAFETY: called once at binary startup, before any threads are created.
    unsafe {
        libc::umask(0o077);
    }
}
pub fn wait(fd: BorrowedFd<'_>, events: i16, timeout: Duration) -> io::Result<i16> {
    let mut descriptor = libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    };
    let timeout = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: descriptor points to one initialized pollfd valid for this call.
    let rc = unsafe { libc::poll(&mut descriptor, 1, timeout) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(descriptor.revents)
    }
}
pub fn read(fd: BorrowedFd<'_>, bytes: &mut [u8]) -> io::Result<usize> {
    // SAFETY: mutable slice is writable for exactly bytes.len(); borrowed fd stays live.
    let rc = unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}
pub fn write(fd: BorrowedFd<'_>, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: slice is readable for exactly bytes.len(); borrowed fd stays live.
    let rc = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}
pub fn flush_input(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: tcflush only operates on the live borrowed terminal descriptor.
    if unsafe { libc::tcflush(fd.as_raw_fd(), libc::TCIFLUSH) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    // SAFETY: flock operates on a live file descriptor and has no memory arguments.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn pidfd(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes numeric arguments, and returns a new fd on success.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pidfd_open transferred this new descriptor's unique ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
#[derive(Debug)]
pub struct Event {
    pub fd: Option<OwnedFd>,
    pub pid: i32,
    pub mask: u64,
}

fn parse_events(mut bytes: &[u8]) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 24 {
            bail!("truncated fanotify metadata");
        }
        let event_len = u32::from_ne_bytes(bytes[0..4].try_into()?) as usize;
        let metadata_len = u16::from_ne_bytes(bytes[6..8].try_into()?) as usize;
        if bytes[4] != libc::FANOTIFY_METADATA_VERSION
            || metadata_len < 24
            || event_len < metadata_len
            || event_len > bytes.len()
        {
            bail!("invalid fanotify metadata length or version");
        }
        let mask = u64::from_ne_bytes(bytes[8..16].try_into()?);
        let raw = i32::from_ne_bytes(bytes[16..20].try_into()?);
        let pid = i32::from_ne_bytes(bytes[20..24].try_into()?);
        let fd = if raw >= 0 {
            // SAFETY: fanotify read transfers unique ownership of each event fd.
            // This function is used only on buffers returned by that read.
            Some(unsafe { OwnedFd::from_raw_fd(raw) })
        } else {
            None
        };
        if fd.is_none() && mask & libc::FAN_OPEN_PERM != 0 {
            bail!("permission event has no fd");
        }
        events.push(Event { fd, pid, mask });
        bytes = &bytes[event_len..];
    }
    Ok(events)
}

pub struct Fanotify {
    fd: OwnedFd,
}
impl Fanotify {
    pub fn ignore_file(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: group fd is live and path is a valid NUL-terminated string.
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD
                    | libc::FAN_MARK_IGNORED_MASK
                    | libc::FAN_MARK_IGNORED_SURV_MODIFY,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("exclude SQLite inode from fanotify");
        }
        Ok(())
    }
    pub fn new() -> Result<Self> {
        // SAFETY: arguments are ABI flags, and success returns a newly owned group fd.
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context(
            "fanotify_init requires initial-namespace CAP_SYS_ADMIN and CONFIG_FANOTIFY_ACCESS_PERMISSIONS");
        }
        // SAFETY: fanotify_init succeeded and transferred the new fd to this owner.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }
    pub fn mark_filesystem(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: group fd is live; path is a NUL-terminated string valid through the call.
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN_PERM | libc::FAN_ONDIR,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error).context("mark fanotify filesystem (Linux 4.20+)");
            }
        }
        Ok(())
    }
    pub fn events(&self) -> Result<Vec<Event>> {
        let mut buffer = [0u8; 65536];
        match read(self.fd.as_fd(), &mut buffer) {
            Ok(0) => bail!("fanotify group closed unexpectedly"),
            Ok(n) => parse_events(&buffer[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e).context("read fanotify events"),
        }
    }
    pub fn respond(&self, event: &OwnedFd, allow: bool) -> Result<()> {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&event.as_raw_fd().to_ne_bytes());
        bytes[4..].copy_from_slice(
            &(if allow {
                libc::FAN_ALLOW
            } else {
                libc::FAN_DENY
            })
            .to_ne_bytes(),
        );
        loop {
            match write(self.fd.as_fd(), &bytes) {
                Ok(8) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("write fanotify response"),
                Ok(_) => bail!("short fanotify response write"),
            }
        }
    }
    pub fn poll(&self, wake: BorrowedFd<'_>, timeout: Duration) -> io::Result<(i16, i16)> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two initialized pollfds are writable and both borrowed fds remain live.
        let rc = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                2,
                timeout.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((descriptors[0].revents, descriptors[1].revents))
        }
    }
}

pub fn mount_points() -> Result<Vec<PathBuf>> {
    let bytes = fs::read("/proc/self/mountinfo").context("read mount table")?;
    bytes
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let field = line
                .split(|&b| b == b' ')
                .nth(4)
                .context("invalid mount table")?;
            let mut decoded = Vec::new();
            let mut i = 0;
            while i < field.len() {
                if field[i] == b'\\' {
                    let octal = field.get(i + 1..i + 4).context("truncated mount escape")?;
                    if !octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                        bail!("invalid mount escape");
                    }
                    let value = ((octal[0] - b'0') as u16) * 64
                        + ((octal[1] - b'0') as u16) * 8
                        + (octal[2] - b'0') as u16;
                    decoded.push(u8::try_from(value)?);
                    i += 4;
                } else {
                    decoded.push(field[i]);
                    i += 1;
                }
            }
            Ok(PathBuf::from(OsString::from_vec(decoded)))
        })
        .collect()
}

pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: array is writable for two descriptors; successful pipe2 creates both.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded; each distinct descriptor is adopted exactly once.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_metadata_without_casting() {
        for n in 0..24 {
            if n != 0 {
                assert!(parse_events(&vec![0; n]).is_err());
            }
        }
        let mut bytes = [0u8; 24];
        bytes[..4].copy_from_slice(&24u32.to_ne_bytes());
        bytes[4] = libc::FANOTIFY_METADATA_VERSION;
        bytes[6..8].copy_from_slice(&24u16.to_ne_bytes());
        bytes[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        assert_eq!(parse_events(&bytes).unwrap().len(), 1);
        bytes[4] = 0;
        assert!(parse_events(&bytes).is_err());
        bytes[4] = libc::FANOTIFY_METADATA_VERSION;
        bytes[8..16].copy_from_slice(&libc::FAN_OPEN_PERM.to_ne_bytes());
        assert!(parse_events(&bytes).is_err());
        bytes[..4].copy_from_slice(&128u32.to_ne_bytes());
        assert!(parse_events(&bytes).is_err());
    }
    #[test]
    fn mount_table_and_pidfd_are_readable() {
        assert!(mount_points().unwrap().contains(&PathBuf::from("/")));
        let fd = pidfd(std::process::id() as i32).unwrap();
        assert_eq!(wait(fd.as_fd(), libc::POLLIN, Duration::ZERO).unwrap(), 0);
    }
}
