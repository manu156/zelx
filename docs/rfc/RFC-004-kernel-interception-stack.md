# RFC-004 — Kernel Interception Stack: fanotify vs seccomp_unotify vs BPF-LSM

**Status:** `Accepted`
**Decision:** Keep fanotify (Phase 0) and seccomp notification (Phase 4) as synchronous brokers; add BPF-LSM enforcement in Phase 5. Replacing a broker requires a validated equivalent mechanism. No traditional kernel module is planned.

---

## Problem

Zelx needs to synchronously intercept process resource access at the kernel level.
"Synchronously" means: **freeze the process before the access completes**, not
log after the fact.

Fanotify and seccomp notification provide userspace decision round trips. BPF-LSM
provides kernel policy hooks; it is not an interchangeable interactive broker.

---

## Mechanism Comparison

| Property | fanotify FAN_OPEN_PERM | seccomp_unotify | BPF-LSM |
|---|---|---|---|
| **Kernel version** | 4.20+ for this implementation | 5.0+ base API; probe required features | 5.7+ base API; probe required hooks/helpers |
| **Waits for a userspace permission response?** | Yes | Yes | No general prompt primitive supplied by sleepable BPF |
| **Coverage: filesystem** | Supported opens with FAN_OPEN_PERM | Partial (needs syscall list) | Selected available LSM hooks |
| **Coverage: network** | ❌ No | ✅ connect/bind/send | ✅ socket hooks |
| **Coverage: process signals** | ❌ No | ✅ kill/tgkill | ✅ security_task_kill |
| **Coverage: IPC** | No | Partial | Selected LSM hooks; protocol brokers still needed |
| **Performance** | Measure complete round trip | Measure complete round trip | Measure hooks plus any retained broker |
| **Identity trust** | Requires verified instance mapping | Requires verified instance mapping and safe argument handling | Requires verified instance mapping and complete policy keys |
| **Deadlock risk** | Requires a responsive reader and self-open/storage exclusions | Requires careful broker and syscall design | Hook/helper and broker composition must be validated |
| **Traditional kernel module?** | ❌ No | ❌ No | ❌ No |
| **Implementation complexity** | Low | Medium | High |

---

## Decision: Layered Progression

### Phase 0–3: fanotify FAN_OPEN_PERM

Use `fanotify` for the MVP because:
- This implementation requires Linux ≥ 4.20 for filesystem marks
- Filesystem is the highest-priority permission to protect (`~/.ssh`, credentials)
- Minimal implementation complexity
- Proven in production (Dropbox, antivirus tools, etc.)

**Critical: deadlock prevention**

`zelxd` must never open a file under its own watched path while handling an event.
This causes a deadlock: the kernel is waiting for `zelxd` to respond, but `zelxd`
is waiting for the kernel to complete its own file open.

Prevention:
```c
// Exempt zelxd's own PID from all fanotify events
if (metadata->pid == getpid()) {
    write_allow(fan_fd, metadata->fd);
    return;
}
// Also exempt the overlay and compositor PIDs (stored at startup)
```

The actual implementation uses a dedicated reader plus a policy/database worker
(see RFC-005). A PID check alone cannot prevent a reader thread from blocking
on its own open before it can read that event. Kernel ABI snippets below are
illustrative C; the user-space implementation is Rust.

Use `O_PATH` for the zelxd's internal file operations where possible (doesn't
trigger `FAN_OPEN_PERM`).

### Phase 4: seccomp_unotify

Add `seccomp_unotify` for:
- `connect()` — outbound network connections
- `bind()` — listening sockets
- `socket(AF_PACKET, ...)` — raw network access
- `execve()` — spawning new binaries (audit + optional restriction)
- `kill()`, `tgkill()` — signal sending (until BPF-LSM in Phase 5)

**Why not use seccomp_unotify for files instead of fanotify?**
- `fanotify` is path-based (you specify which directory to watch)
- `seccomp_unotify` would require intercepting `open()`, `openat()`, `openat2()`,
  `creat()`, `truncate()` — many syscall variants, easy to miss one
- `fanotify` has filesystem-level hooks that catch all variants automatically

**Argument parsing for network:**
```c
// Read sockaddr from frozen process's address space
struct sockaddr_storage addr;
process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
// Parse addr.ss_family, resolve hostname, build display string
```

### Phase 5: BPF-LSM

Add established-policy enforcement, additional hooks for signaling/ptrace, and
auditing. Keep fanotify for interactive file decisions and seccomp notification
for the selected syscall decisions. Passing a BPF hook does not skip the existing
broker, so latency improvements must be measured for the composed system.

`BPF_F_SLEEPABLE` permits supported sleeping helpers/kfuncs in allowed contexts;
it does not create a wait-for-userspace decision API. Do not assume that an
arbitrary hook can sleep or that kernel 5.11 supplies a synchronous prompt path.
See [kernel kfunc documentation](https://kernel.org/doc/html/latest/bpf/kfuncs.html).

Unknown policy must reach a guaranteed active broker or deny. Never allow a first
access to populate a cache. Broker replacement requires a runnable prototype and
equivalent coverage, timeout, crash, revocation, and audit tests. See the revised
[Phase 5 plan](../phases/phase-5-bpf-lsm.md).

---

## Kernel extension scope

No traditional kernel module is planned. Available BPF-LSM hooks and the retained
brokers are the design direction; exact coverage must be validated. A custom
kernel mechanism would require a separate feasibility and maintenance decision,
including:

- Matching kernel headers per distro/version
- Secure Boot signing requirements
- DKMS rebuild on every kernel update
- Contributor requirements for a kernel build environment

Do not treat this direction as proof that every proposed BPF helper or prompt
mechanism exists. Feasibility gaps must be resolved before accepting a phase.

---

## Kernel Version Requirements Per Phase

| Phase | Minimum Kernel | Config Flags Required |
|---|---|---|
| Phase 0–3 | 4.20 (filesystem marks) | `CONFIG_FANOTIFY=y`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` |
| Phase 4 | 5.0 | None (seccomp_unotify is mainline) |
| Phase 5 | 5.7 (BPF-LSM) | `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| Phase 5 (interactive) | Existing fanotify/seccomp brokers retained | Sleepable BPF alone is not a replacement |
| Phase 6 | 5.0 (user namespaces) | `CONFIG_USER_NS=y` (default on most distros) |

Probe the running kernel and active security configuration. A distribution name
or version alone does not establish that all required features are available.
