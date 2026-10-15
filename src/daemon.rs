#![forbid(unsafe_code)]
use crate::{
    db::{AuditEvent, Database, Decision, Resource},
    identity::AppIdentity,
    linux::{self, Fanotify},
    policy::{path_under, Policy},
    prompt::{Answer, Prompt},
    DEFAULT_DB,
};
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(about = "Linux filesystem audit and runtime permissions")]
pub struct Options {
    #[arg(long)]
    pub audit_only: bool,
    #[arg(long, value_name = "DIR")]
    pub watch: Vec<PathBuf>,
    #[arg(long,default_value=DEFAULT_DB)]
    pub db: PathBuf,
    #[arg(long)]
    pub tty: Option<PathBuf>,
    #[arg(long,default_value="30",value_parser=clap::value_parser!(u64).range(1..=300))]
    pub timeout: u64,
    #[arg(long,value_parser=clap::value_parser!(i32).range(2..))]
    pub exempt_pid: Vec<i32>,
}
#[derive(Clone, Copy, Debug)]
struct Outcome {
    decision: Decision,
    accepted: bool,
    latency_us: i64,
}
struct Job {
    id: u64,
    identity: AppIdentity,
    path: String,
    ts: i64,
    deadline: Instant,
    immediate: Option<Outcome>,
}
struct Pending {
    fd: OwnedFd,
    started: Instant,
    deadline: Instant,
}
struct RequestedDecision {
    id: u64,
    decision: Decision,
    reply: SyncSender<Outcome>,
}
fn latency(start: Instant) -> i64 {
    start.elapsed().as_micros().min(i64::MAX as u128) as i64
}

fn worker(
    mut policy: Policy,
    prompt: Option<Prompt>,
    jobs: Receiver<Job>,
    decisions: Sender<RequestedDecision>,
    wake: OwnedFd,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    for job in jobs {
        let mut prompted = false;
        let mut answer = None;
        let mut rule_id = None;
        let outcome = if let Some(outcome) = job.immediate {
            outcome
        } else {
            let mut decision = Decision::Deny;
            if !stop.load(Ordering::Relaxed) && Instant::now() < job.deadline {
                match policy.lookup(&job.identity.comm, Resource::Filesystem, &job.path) {
                    Ok(Some(evaluation)) => {
                        decision = evaluation.decision;
                        rule_id = evaluation.rule_id;
                    }
                    Ok(None) => {
                        prompted = true;
                        let response = prompt
                            .as_ref()
                            .map(|p| p.request(&job.identity, &job.path, job.deadline, &stop))
                            .unwrap_or(Answer::DENY);
                        decision = response.decision;
                        answer = Some(response);
                    }
                    Err(error) => eprintln!("Policy lookup failed; denying: {error:#}"),
                }
            }
            let (reply, acknowledgement) = mpsc::sync_channel(1);
            decisions
                .send(RequestedDecision {
                    id: job.id,
                    decision,
                    reply,
                })
                .context("event reader stopped")?;
            match linux::write(wake.as_fd(), &[1]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error).context("wake event reader"),
            }
            acknowledgement
                .recv()
                .context("event reader failed to acknowledge decision")?
        };
        if !outcome.accepted {
            rule_id = None;
        }
        if outcome.accepted && !stop.load(Ordering::Relaxed) {
            if let Some(answer) = answer {
                match policy.save(&job.identity.comm, &job.path, answer.decision, answer.scope) {
                    Ok(id) => rule_id = id,
                    Err(error) => eprintln!("Rule was not saved: {error:#}"),
                }
            }
        }
        let label = match (prompted, outcome.decision) {
            (true, Decision::Allow) => "PROMPT_ALLOW",
            (true, Decision::Deny) => "PROMPT_DENY",
            (false, Decision::Allow) => "ALLOW",
            (false, Decision::Deny) => "DENY",
        };
        policy
            .database
            .audit(AuditEvent {
                ts: job.ts,
                app: &job.identity.comm,
                pid: job.identity.pid,
                target: &job.path,
                decision: label,
                rule_id,
                latency_us: outcome.latency_us,
            })
            .context("AUDIT WRITE FAILED; stopping")?;
    }
    Ok(())
}

fn receive_decisions(
    group: Option<&Fanotify>,
    decisions: &Receiver<RequestedDecision>,
    pending: &mut HashMap<u64, Pending>,
    completed: &mut HashMap<u64, Outcome>,
    stop: &AtomicBool,
) -> Result<()> {
    for request in decisions.try_iter() {
        let outcome = if let Some(event) = pending.remove(&request.id) {
            let accepted = !stop.load(Ordering::Relaxed) && Instant::now() < event.deadline;
            let decision = if accepted {
                request.decision
            } else {
                Decision::Deny
            };
            let result = group
                .context("fanotify group closed with pending event")?
                .respond(&event.fd, decision.allowed());
            let outcome = Outcome {
                decision,
                accepted: accepted && result.is_ok(),
                latency_us: latency(event.started),
            };
            // Always acknowledge, including response failure, so shutdown cannot strand the worker.
            let _ = request.reply.send(outcome);
            result?;
            continue;
        } else {
            completed
                .remove(&request.id)
                .context("decision for unknown request")?
        };
        let _ = request.reply.send(outcome);
    }
    Ok(())
}

fn trusted_storage(path: &Path) -> Result<bool> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let resolved = fs::canonicalize(parent)?;
    for (index, ancestor) in resolved.ancestors().enumerate() {
        let meta = fs::metadata(ancestor)?;
        if !meta.is_dir()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0 && (index == 0 || meta.mode() & 0o1000 == 0)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn prepare_storage(path: &Path) -> Result<File> {
    if path == Path::new(DEFAULT_DB) {
        match fs::DirBuilder::new().mode(0o700).create("/var/lib/zelx") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).context("create /var/lib/zelx (run privileged or use --db)"),
        }
    }
    if linux::effective_uid() == 0 && !trusted_storage(path)? {
        bail!("root daemon requires a root-owned database directory and trusted parents");
    }
    match fs::symlink_metadata(path) {
        Ok(meta)
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || meta.uid() != linux::effective_uid()
                || meta.mode() & 0o077 != 0 =>
        {
            bail!("database must be a private owned regular file (mode 0600)")
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock)
        .context("open database daemon lock")?;
    linux::lock_exclusive(&file).context("database already has an active daemon")?;
    Ok(file)
}
fn dedicated_cgroup(identity: &AppIdentity) -> bool {
    let base = Path::new(&identity.cgroup)
        .file_name()
        .and_then(|s| s.to_str());
    if linux::effective_uid() != 0 || !matches!(base, Some("zelxd.service" | "zelxd.scope")) {
        return false;
    }
    let procs = Path::new("/sys/fs/cgroup")
        .join(identity.cgroup.trim_start_matches('/'))
        .join("cgroup.procs");
    trusted_storage(&procs).unwrap_or(false)
        && fs::metadata(procs).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
}

pub fn run(mut options: Options) -> Result<()> {
    if options.watch.len() > 64 || options.exempt_pid.len() > 64 {
        bail!("maximum 64 watch roots and PID exemptions");
    }
    if options.watch.is_empty() {
        options.watch.push(PathBuf::from("/home"));
    }
    let roots: Vec<_> = options
        .watch
        .iter()
        .map(|path| {
            let path = fs::canonicalize(path)
                .with_context(|| format!("resolve watch root {}", path.display()))?;
            if !path.is_dir()
                || ["/proc", "/sys", "/dev"]
                    .iter()
                    .any(|p| path_under(&path, Path::new(p)))
            {
                bail!("watch root must be an ordinary existing directory");
            }
            Ok(path)
        })
        .collect::<Result<_>>()?;
    linux::private_umask();
    let _lock = prepare_storage(&options.db)?;
    let database = Database::open(&options.db, false)?;
    let prompt = Prompt::open(options.tty.as_deref())?;
    let exemptions: Vec<_> = options
        .exempt_pid
        .iter()
        .map(|&pid| Ok((pid, linux::pidfd(pid).context("pidfd_open exemption")?)))
        .collect::<Result<_>>()?;
    let self_identity = AppIdentity::resolve(std::process::id() as i32);
    let dedicated = dedicated_cgroup(&self_identity);
    let group = Fanotify::new()?;
    // Do this before adding any filesystem marks. Fanotify event descriptors
    // are ordinary open files; closing one for a SQLite inode would release
    // this process's POSIX locks, including locks held by the policy worker.
    // The live WAL connection keeps these sidecars present until shutdown.
    for suffix in ["", "-wal", "-shm"] {
        let mut path = options.db.as_os_str().to_os_string();
        path.push(suffix);
        group.ignore_file(Path::new(&path))?;
    }
    for root in &roots {
        group.mark_filesystem(root)?;
    }
    for mount in linux::mount_points()? {
        if roots.iter().any(|root| path_under(&mount, root)) {
            group
                .mark_filesystem(&mount)
                .context("mark nested filesystem")?;
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signals: Vec<_> = [libc::SIGINT, libc::SIGTERM]
        .into_iter()
        .map(|signal| signal_hook::flag::register(signal, stop.clone()))
        .collect::<io::Result<_>>()?;
    let (jobs_tx, jobs_rx) = mpsc::channel();
    let (decisions_tx, decisions_rx) = mpsc::channel();
    let (wake_rx, wake_tx) = linux::pipe()?;
    let cancel = stop.clone();
    let worker = thread::Builder::new()
        .name("zelx-policy".into())
        .spawn(move || {
            worker(
                Policy::new(database),
                prompt,
                jobs_rx,
                decisions_tx,
                wake_tx,
                cancel,
            )
        })?;
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut completed = HashMap::new();
    let mut next_id = 0u64;
    eprintln!(
        "zelxd ready: mode={} roots={} timeout={}s",
        if options.audit_only {
            "audit"
        } else {
            "enforce"
        },
        roots.len(),
        options.timeout
    );
    let mut result = (|| -> Result<()> {
        while !stop.load(Ordering::Relaxed) {
            if worker.is_finished() {
                bail!("policy/audit worker stopped unexpectedly");
            }
            receive_decisions(
                Some(&group),
                &decisions_rx,
                &mut pending,
                &mut completed,
                &stop,
            )?;
            let expired: Vec<_> = pending
                .iter()
                .filter(|(_, e)| Instant::now() >= e.deadline)
                .map(|(&id, _)| id)
                .collect();
            for id in expired {
                let event = pending.remove(&id).expect("expired event is pending");
                group.respond(&event.fd, false)?;
                completed.insert(
                    id,
                    Outcome {
                        decision: Decision::Deny,
                        accepted: false,
                        latency_us: latency(event.started),
                    },
                );
            }
            match group.poll(wake_rx.as_fd(), Duration::from_millis(25)) {
                Ok((flags, _)) if flags & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 => {
                    bail!("fanotify poll failed")
                }
                Ok((flags, wake)) => {
                    if wake & libc::POLLIN != 0 {
                        let mut bytes = [0; 128];
                        let _ = linux::read(wake_rx.as_fd(), &mut bytes);
                    }
                    if flags == 0 {
                        continue;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            for event in group.events()? {
                if event.mask & libc::FAN_Q_OVERFLOW != 0 {
                    bail!("FANOTIFY QUEUE OVERFLOW: audit/enforcement coverage lost");
                }
                let Some(fd) = event.fd else {
                    continue;
                };
                if event.mask & libc::FAN_OPEN_PERM == 0 {
                    continue;
                }
                let exempt = event.pid == self_identity.pid
                    || event.pid == 1
                    || exemptions.iter().any(|(pid, fd)| {
                        *pid == event.pid
                            && linux::wait(fd.as_fd(), libc::POLLIN, Duration::ZERO)
                                .is_ok_and(|flags| flags == 0)
                    });
                if exempt {
                    group.respond(&fd, true)?;
                    continue;
                }
                let started = Instant::now();
                let ts = crate::now_ms();
                let deadline = started + Duration::from_secs(options.timeout);
                let path = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok();
                if path
                    .as_ref()
                    .is_some_and(|path| !roots.iter().any(|root| path_under(path, root)))
                {
                    group.respond(&fd, true)?;
                    continue;
                }
                let identity = AppIdentity::resolve(event.pid);
                if dedicated && identity.cgroup == self_identity.cgroup {
                    group.respond(&fd, true)?;
                    continue;
                }
                let valid = path.as_ref().and_then(|p| p.to_str());
                let target = match &path {
                    Some(path) => valid.map(str::to_owned).unwrap_or_else(|| {
                        format!("<non-utf8:{}>", crate::escaped(path.as_os_str().as_bytes()))
                    }),
                    None => "<unresolved>".into(),
                };
                let immediate = if options.audit_only || valid.is_none() {
                    let decision = if options.audit_only {
                        Decision::Allow
                    } else {
                        Decision::Deny
                    };
                    group.respond(&fd, decision.allowed())?;
                    Some(Outcome {
                        decision,
                        accepted: false,
                        latency_us: latency(started),
                    })
                } else {
                    None
                };
                next_id = next_id.checked_add(1).context("request ID exhausted")?;
                if immediate.is_none() {
                    pending.insert(
                        next_id,
                        Pending {
                            fd,
                            started,
                            deadline,
                        },
                    );
                }
                jobs_tx
                    .send(Job {
                        id: next_id,
                        identity,
                        path: target,
                        ts,
                        deadline,
                        immediate,
                    })
                    .context("policy worker unavailable")?;
            }
        }
        Ok(())
    })();
    if let Err(error) = &result {
        // Report loss of interception before closing the group or draining the worker.
        eprintln!("Event reader failed; stopping interception: {error:#}");
    }
    stop.store(true, Ordering::Relaxed);
    // Respond to received events before closing the group. The group has exactly
    // one owner; unread kernel requests are released when it is dropped.
    for (id, event) in pending.drain() {
        if let Err(error) = group.respond(&event.fd, false) {
            result = Err(error);
        }
        completed.insert(
            id,
            Outcome {
                decision: Decision::Deny,
                accepted: false,
                latency_us: latency(event.started),
            },
        );
    }
    drop(group);
    drop(jobs_tx);
    // A prompt/DB operation may finish during shutdown. Keep acknowledging its
    // messages while it drains the queue, without leaving a kernel group open.
    while !worker.is_finished() {
        if let Err(error) =
            receive_decisions(None, &decisions_rx, &mut pending, &mut completed, &stop)
        {
            result = Err(error);
        }
        thread::sleep(Duration::from_millis(10));
    }
    for signal in signals {
        signal_hook::low_level::unregister(signal);
    }
    match worker.join() {
        Ok(Ok(())) => result,
        Ok(Err(error)) => Err(error),
        Err(_) => bail!("policy/audit worker panicked"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
    #[test]
    fn storage_permissions_and_duplicate_daemon_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let lock = prepare_storage(&path).unwrap();
        assert!(prepare_storage(&path).is_err());
        drop(lock);
        fs::write(&path, b"not used").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(prepare_storage(&path).is_err());
    }
    #[test]
    fn paths_preserve_bytes_and_component_boundaries() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/home/me/secret\xff".to_vec(),
        ));
        assert!(path_under(&path, Path::new("/home/me")));
        assert!(path.to_str().is_none());
        assert_eq!(
            crate::escaped(path.as_os_str().as_bytes()),
            "/home/me/secret\\xff"
        );
    }
}
