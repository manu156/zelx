# Phase 0 — fanotify Intercept & Audit Logging

**Status:** Rust implementation — baseline real-kernel regression suite passed;
manual desktop smoke checks below remain separate.
See the [runtime guide](../runtime.md) for usage, validation results, and limits.
**Goal:** Prove the kernel interception chain is real and shippable.

---

## Objective

In passive mode (`zelxd --audit-only`), the daemon:
1. Intercepts every `open()` call touching `$HOME` using `fanotify FAN_OPEN_PERM`
2. Auto-allows everything (no prompting yet)
3. Logs every event to SQLite with app identity and timestamp
4. A CLI tool (`zelxctl`) that reads the log and shows what any app touched

This phase produces **zero user-visible security** but proves the plumbing.
It is the foundation every subsequent phase builds on.

---

## Components

| Component | Implementation |
|---|---|
| `src/bin/zelxd.rs`, `src/daemon.rs`, `src/linux.rs` | Rust daemon and Linux ABI boundary |
| `src/db.rs`, `src/policy.rs`, `src/identity.rs` | Shared Rust runtime library |
| `src/bin/zelxctl.rs` | Rust audit and policy CLI |
| `src/bin/zelx-run.rs` | Rust `exec` launcher |
| `Cargo.toml`, `Cargo.lock`, `Makefile` | Cargo build and test wrappers |

See [RFC-005](../rfc/RFC-005-rust-runtime.md) for ownership and migration decisions.

---

## Implementation Plan

### 1. `zelxd` — fanotify event loop

```rust
// linux.rs owns the small unsafe syscall boundary.
let group = Fanotify::new()?;
group.mark_filesystem(std::path::Path::new("/home"))?;
// Reader owns permission descriptors; worker owns policy, prompts, and SQLite.
```

Key details:
- Use `FAN_OPEN_PERM` (not `FAN_OPEN`) — this **freezes** the calling thread
- Resolve PID → `/proc/<pid>/cgroup` → cgroup path → app name
- Respond with `FAN_ALLOW` immediately (no prompt in Phase 0)
- Write to SQLite asynchronously (don't block the allow response)

### 2. Identity resolution (basic, PID-based)

Read `/proc/<pid>/comm` for the process name.
Read `/proc/<pid>/cgroup` for future cgroup identity (Phase 2 will use this fully).

```rust
pub struct AppIdentity {
    pub pid: i32,
    pub comm: String,
    pub cgroup: String,
    pub exe: std::path::PathBuf,
}
```

### 3. SQLite audit schema

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,          -- Unix ms timestamp
    app_id      TEXT    NOT NULL,          -- cgroup path or comm name
    pid         INTEGER NOT NULL,
    resource    TEXT    NOT NULL,          -- "filesystem", "network", etc.
    target      TEXT    NOT NULL,          -- path or address
    decision    TEXT    NOT NULL,          -- ALLOW | DENY | PROMPT
    rule_id     INTEGER                    -- FK to rules table (nullable)
);

CREATE TABLE rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id      TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    target_glob TEXT    NOT NULL,          -- e.g. "/home/user/.ssh/**"
    decision    TEXT    NOT NULL,          -- ALLOW | DENY
    scope       TEXT    NOT NULL,          -- ONCE | SESSION | ALWAYS
    created_at  INTEGER NOT NULL
);
```

### 4. `zelxctl trace` command

```bash
zelxctl trace discord
zelxctl trace discord --last 1h
zelxctl trace --all --last 5m          # everything, last 5 minutes
```

Output:
```
TIMESTAMP            APP       DECISION  RESOURCE    TARGET
2026-10-14 16:41:02  discord   ALLOW     filesystem  /usr/lib/libssl.so.3
2026-10-14 16:40:58  discord   ALLOW     filesystem  /home/user/.config/discord/settings.json
```

### 5. Exemption list (critical — prevents deadlocks)

`zelxd` must never intercept its own file opens. Hard-code an exemption for:
- `zelxd`'s own PID (set at startup)
- Any PID in a dedicated, root-controlled `zelxd` service cgroup
  (never a shared user-session cgroup)
- System paths: `/proc`, `/sys`, `/dev`

```rust
if event.pid == std::process::id() as i32 {
    group.respond(&event.fd, true)?;
    continue; // OwnedFd closes on scope exit; no self-audit entry.
}
```

---

## `zelx-run` (Phase 0 — minimal)

A Rust launcher sets `ZELX_APP_ID` to the command basename and uses
`std::os::unix::process::CommandExt::exec`. It preserves argument bytes, PID,
signals, and command exit status. This is an informational hint, not trusted
identity. Cgroup creation remains Phase 2.

---

## Success Criteria

- [ ] `sudo zelxd --audit-only &` starts without crashing
- [ ] `zelx-run discord` + `zelxctl trace discord` shows all files discord opened
- [ ] `zelxd` does NOT appear in its own audit log
- [ ] Killing `zelxd` mid-run does not leave any process frozen indefinitely
  (fanotify auto-allows pending events when the fd is closed)
- [x] `zelxctl trace --last 1h` is readable and sorted correctly (CLI tests)

---

## Known Limitations in This Phase

- Identity is PID-based (not cgroup): child processes appear as separate apps
- No policy enforcement — everything is allowed
- No Wayland prompt
- `zelxd` must run as root
- Network access is not intercepted
- `/tmp` is not watched
