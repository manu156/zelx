#![forbid(unsafe_code)]
use crate::{
    db::{Decision, Scope},
    identity::AppIdentity,
    linux,
};
use anyhow::{bail, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{self, IsTerminal},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub decision: Decision,
    pub scope: Scope,
}
impl Answer {
    pub const DENY: Self = Self {
        decision: Decision::Deny,
        scope: Scope::Once,
    };
}
pub struct Prompt {
    input: File,
    output: File,
}
impl Prompt {
    pub fn open(tty: Option<&Path>) -> Result<Option<Self>> {
        if let Some(path) = tty {
            let input = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(
                    libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
                .open(path)
                .context("open --tty terminal")?;
            if !input.is_terminal() {
                bail!("--tty must name a terminal");
            }
            let output = input.try_clone()?;
            return Ok(Some(Self { input, output }));
        }
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return Ok(None);
        }
        // Reopen procfs descriptions so O_NONBLOCK never alters the caller's flags.
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/proc/self/fd/0")?;
        let output = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/proc/self/fd/2")?;
        Ok(Some(Self { input, output }))
    }
    pub fn request(
        &self,
        identity: &AppIdentity,
        path: &str,
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Answer {
        request(
            self.input.as_fd(),
            self.output.as_fd(),
            identity,
            path,
            deadline,
            stop,
            self.input.is_terminal(),
        )
    }
}
fn ready(fd: BorrowedFd<'_>, events: i16, deadline: Instant, stop: &AtomicBool) -> bool {
    while !stop.load(Ordering::Relaxed) {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        match linux::wait(fd, events, left.min(Duration::from_millis(100))) {
            Ok(revents) if revents != 0 => return revents & events != 0,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    false
}
fn request(
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    identity: &AppIdentity,
    path: &str,
    deadline: Instant,
    stop: &AtomicBool,
    terminal: bool,
) -> Answer {
    if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
        return Answer::DENY;
    }
    if terminal && linux::flush_input(input).is_err() {
        return Answer::DENY;
    }
    let text = format!("\nZELX PERMISSION REQUEST\nApp: {} (PID {})\nWants: open filesystem\nPath: {}\n[1] Allow once  [2] Allow always  [3] Deny once\n[4] Deny always  [5] Allow session\nChoice (timeout denies): ",
        crate::escaped(identity.comm.as_bytes()),identity.pid,crate::escaped(path.as_bytes()));
    let mut remaining = text.as_bytes();
    while !remaining.is_empty() {
        if !ready(output, libc::POLLOUT, deadline, stop) {
            return Answer::DENY;
        }
        match linux::write(output, remaining) {
            Ok(0) => return Answer::DENY,
            Ok(n) => remaining = &remaining[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Answer::DENY,
        }
    }
    let mut line = Vec::new();
    while ready(input, libc::POLLIN, deadline, stop) {
        let mut byte = [0];
        match linux::read(input, &mut byte) {
            Ok(1) => {
                if byte[0] == b'\n' {
                    return match line.as_slice() {
                        b"1" => Answer {
                            decision: Decision::Allow,
                            scope: Scope::Once,
                        },
                        b"2" => Answer {
                            decision: Decision::Allow,
                            scope: Scope::Always,
                        },
                        b"4" => Answer {
                            decision: Decision::Deny,
                            scope: Scope::Always,
                        },
                        b"5" => Answer {
                            decision: Decision::Allow,
                            scope: Scope::Session,
                        },
                        _ => Answer::DENY,
                    };
                }
                if line.len() >= 31 {
                    return Answer::DENY;
                }
                line.push(byte[0]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            _ => return Answer::DENY,
        }
    }
    Answer::DENY
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn choices_timeout_eof_cancellation_and_safe_display() {
        let (input, writer) = linux::pipe().unwrap();
        let (reader, output) = linux::pipe().unwrap();
        let identity = AppIdentity {
            pid: 42,
            comm: "app\x1b[2J".into(),
            cgroup: String::new(),
            exe: Default::default(),
        };
        let stop = AtomicBool::new(false);
        for (choice, decision, scope) in [
            ("1\n", Decision::Allow, Scope::Once),
            ("2\n", Decision::Allow, Scope::Always),
            ("3\n", Decision::Deny, Scope::Once),
            ("4\n", Decision::Deny, Scope::Always),
            ("5\n", Decision::Allow, Scope::Session),
            ("bad\n", Decision::Deny, Scope::Once),
        ] {
            linux::write(writer.as_fd(), choice.as_bytes()).unwrap();
            let answer = request(
                input.as_fd(),
                output.as_fd(),
                &identity,
                "/secret\nspoof",
                Instant::now() + Duration::from_millis(100),
                &stop,
                false,
            );
            assert_eq!(answer, Answer { decision, scope });
            let mut bytes = [0; 4096];
            let n = linux::read(reader.as_fd(), &mut bytes).unwrap();
            let text = std::str::from_utf8(&bytes[..n]).unwrap();
            assert!(text.contains("\\x1b") && text.contains("/secret\\x0aspoof"));
            assert!(!text.contains('\x1b'));
        }
        let start = Instant::now();
        assert_eq!(
            request(
                input.as_fd(),
                output.as_fd(),
                &identity,
                "/secret",
                start + Duration::from_millis(35),
                &stop,
                false
            ),
            Answer::DENY
        );
        assert!(start.elapsed() < Duration::from_millis(200));
        drop(writer);
        assert_eq!(
            request(
                input.as_fd(),
                output.as_fd(),
                &identity,
                "/secret",
                Instant::now() + Duration::from_secs(1),
                &stop,
                false
            ),
            Answer::DENY
        );
        stop.store(true, Ordering::Relaxed);
        assert_eq!(
            request(
                input.as_fd(),
                output.as_fd(),
                &identity,
                "/secret",
                Instant::now() + Duration::from_secs(1),
                &stop,
                false
            ),
            Answer::DENY
        );
    }
    #[test]
    fn blocked_output_has_a_deadline() {
        let (input, _writer) = linux::pipe().unwrap();
        let (_reader, output) = linux::pipe().unwrap();
        while linux::write(output.as_fd(), &[0; 4096]).is_ok() {}
        let identity = AppIdentity::resolve(std::process::id() as i32);
        let start = Instant::now();
        assert_eq!(
            request(
                input.as_fd(),
                output.as_fd(),
                &identity,
                "/secret",
                start + Duration::from_millis(35),
                &AtomicBool::new(false),
                false
            ),
            Answer::DENY
        );
        assert!(start.elapsed() < Duration::from_millis(200));
    }
}
