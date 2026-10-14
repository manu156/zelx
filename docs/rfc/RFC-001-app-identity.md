# RFC-001 — App Identity: cgroup v2 vs UID vs PID

**Status:** `Accepted`
**Decision:** cgroup v2 slice path is the canonical app identity.

---

## Problem

Every security decision in Zelx is tied to an app identity. The identity must be:
- **Stable** — doesn't change as the app spawns children
- **Unforgeable** — a malicious app cannot claim a different identity
- **Unique** — two different apps cannot share an identity
- **Persistent** — the same app across multiple launches maps to the same policy bucket

## Options Considered

### Option A: PID
**Rejected.**
- PIDs are reused after process exit
- Each child process gets a new PID — all CLI tools inside a terminal appear as separate apps
- Trivially forgeable (a process cannot change its own PID, but children are new)

### Option B: UID per app (Android-style)
**Rejected for MVP; possible long-term.**
- Requires creating a new user account per app — requires root and system-level setup
- Existing apps are not built to run as arbitrary UIDs
- `$HOME` and XDG paths break (Discord expects to find config at `~/.config/discord`, which is owned by the user UID)
- Would require full bind-mount namespace (Phase 6) to work correctly anyway
- Complex to administer

### Option C: cgroup v2 slice (chosen)
**Accepted.**

```
/sys/fs/cgroup/zelx.slice/zelx-discord-a3f2b1c8.scope/
```

**Why this works:**
- `fork()` inherits the cgroup automatically — all children are in the same slice
- Requires `CAP_SYS_ADMIN` to escape — unforgeable in practice
- `zelxd` reads `/proc/<pid>/cgroup` to resolve any PID to its app identity
- Two launches of the same app get different UUIDs but the same base name (`discord`) → same policy rules
- Works on any kernel ≥ 4.5 with cgroup v2

**Policy key derivation:**
```
cgroup path:  zelx-discord-a3f2b1c8.scope
policy key:   discord                         (strip "zelx-" prefix and UUID suffix)
audit key:    discord-a3f2b1c8               (include UUID for instance tracking)
```

## Implementation Notes

- `zelxd` should maintain an in-memory `pid → cgroup_id` cache to avoid
  hitting `/proc/<pid>/cgroup` on every event (hot path optimization)
- The cache must be invalidated on process exit (use `fanotify` `FAN_EVENT_ON_CHILD`
  or a `pidfd` poll to detect exit)
- `zelx-run` creates the cgroup before `exec()` so the app never runs outside it

## Open Questions

- **Q: What about apps not launched via `zelx-run`?**
  A: They fall into the default cgroup and get a policy key of `__unmanaged__`.
  Phase 6 may block `__unmanaged__` apps from accessing protected paths entirely.

- **Q: Can a malicious app write to `/sys/fs/cgroup/` to move itself?**
  A: Only if it has `CAP_SYS_ADMIN`. Zelx drops this capability (Phase 6). Even
  before Phase 6, writing to `cgroup.procs` requires write permission on the target
  cgroup directory, which is owned by root.
