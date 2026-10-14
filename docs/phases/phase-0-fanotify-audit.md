# Phase 0 — fanotify Intercept & Audit Logging

**Status:** `[ ] Not started`
**Goal:** Prove the kernel interception chain is real and shippable.

---

## Objective

A working daemon (`zelxd`) that:
1. Intercepts every `open()` call touching `$HOME` using `fanotify FAN_OPEN_PERM`
2. Auto-allows everything (no prompting yet)
3. Logs every event to SQLite with app identity and timestamp
4. A CLI tool (`zelxctl`) that reads the log and shows what any app touched

This phase produces **zero user-visible security** but proves the plumbing.
It is the foundation every subsequent phase builds on.

---

## Components

| Component | Language | Lines (est.) |
|---|---|---|
| `zelxd/main.c` | C | ~300 |
| `zelxd/audit.c` | C | ~100 |
| `zelxd/identity.c` | C | ~80 |
| `zelxctl/main.c` | C | ~150 |
| `zelx-run` | Shell | ~30 |
| `Makefile` | Make | ~40 |

Total: ~700 lines. **Shippable in a weekend.**

---

## Implementation Plan

### 1. `zelxd` — fanotify event loop

```c
// Setup
int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                           O_RDONLY | O_LARGEFILE | O_CLOEXEC);

fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
              FAN_OPEN_PERM, AT_FDCWD, "/home");

// Event loop: read events, resolve identity, log, respond FAN_ALLOW
```

Key details:
- Use `FAN_OPEN_PERM` (not `FAN_OPEN`) — this **freezes** the calling thread
- Resolve PID → `/proc/<pid>/cgroup` → cgroup path → app name
- Respond with `FAN_ALLOW` immediately (no prompt in Phase 0)
- Write to SQLite asynchronously (don't block the allow response)

### 2. Identity resolution (basic, PID-based)

Read `/proc/<pid>/comm` for the process name.
Read `/proc/<pid>/cgroup` for future cgroup identity (Phase 2 will use this fully).

```c
// identity.c
typedef struct {
    pid_t   pid;
    char    comm[64];       // /proc/<pid>/comm
    char    cgroup[256];    // /proc/<pid>/cgroup
    char    exe[PATH_MAX];  // /proc/<pid>/exe (symlink)
} AppIdentity;
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
- Any PID in the `zelxd` cgroup
- System paths: `/proc`, `/sys`, `/dev`

```c
// Before writing FAN_DENY, always check:
if (event->pid == getpid()) {
    write_allow(fan_fd, event->fd);
    return;
}
```

---

## `zelx-run` (Phase 0 — minimal)

A shell script that just sets an env var for now (cgroup creation is Phase 2):

```bash
#!/bin/bash
# zelx-run: launch an app under zelx supervision
# Phase 0: env var identity only. Phase 2: cgroup slice.
export ZELX_APP_ID="${1##*/}"
exec "$@"
```

---

## Success Criteria

- [ ] `sudo zelxd &` starts without crashing
- [ ] `zelx-run discord` + `zelxctl trace discord` shows all files discord opened
- [ ] `zelxd` does NOT appear in its own audit log
- [ ] Killing `zelxd` mid-run does not leave any process frozen indefinitely
  (fanotify auto-allows pending events when the fd is closed)
- [ ] `zelxctl trace --last 1h` is readable and sorted correctly

---

## Known Limitations in This Phase

- Identity is PID-based (not cgroup): child processes appear as separate apps
- No policy enforcement — everything is allowed
- No Wayland prompt
- `zelxd` must run as root
- Network access is not intercepted
- `/tmp` is not watched
