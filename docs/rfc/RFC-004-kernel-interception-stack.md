# RFC-004 — Kernel Interception Stack: fanotify vs seccomp_unotify vs BPF-LSM

**Status:** `Accepted`
**Decision:** Layered approach — fanotify (Phase 0) → seccomp_unotify (Phase 4) → BPF-LSM (Phase 5). No traditional kernel module.

---

## Problem

Zelx needs to synchronously intercept process resource access at the kernel level.
"Synchronously" means: **freeze the process before the access completes**, not
log after the fact.

Three mechanisms can do this without a traditional `.ko` kernel module.

---

## Mechanism Comparison

| Property | fanotify FAN_OPEN_PERM | seccomp_unotify | BPF-LSM |
|---|---|---|---|
| **Kernel version** | 3.8+ (mature) | 5.0+ | 5.7+ (5.11 for sleepable) |
| **Freezes the process?** | ✅ Yes | ✅ Yes | ✅ Yes (sleepable) |
| **Coverage: filesystem** | ✅ Full (open/read) | Partial (needs syscall list) | ✅ Full (LSM hooks) |
| **Coverage: network** | ❌ No | ✅ connect/bind/send | ✅ socket hooks |
| **Coverage: process signals** | ❌ No | ✅ kill/tgkill | ✅ security_task_kill |
| **Coverage: IPC** | ❌ No | Partial | ✅ security hooks |
| **Performance (cached)** | ~50–200µs/op | ~100–300µs/op | ~1–5µs/op |
| **Spoofing resistance** | High | Medium (arg parsing in user space) | Very high (in-kernel) |
| **Deadlock risk** | Medium (VFS locks) | Low | Low (BPF design avoids this) |
| **Traditional kernel module?** | ❌ No | ❌ No | ❌ No |
| **Implementation complexity** | Low | Medium | High |

---

## Decision: Layered Progression

### Phase 0–3: fanotify FAN_OPEN_PERM

Use `fanotify` for the MVP because:
- Works on every kernel ≥ 3.8 (all modern distros)
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

Replace fanotify with BPF-LSM for:
- More complete file coverage (`security_file_open` catches all variants)
- In-kernel policy cache (dramatic performance improvement)
- Process isolation (`security_task_kill`)
- Anti-ptrace (`security_ptrace_access_check`)
- Lower latency on hot paths (policy cache hit: ~1–5µs vs ~50–200µs)

Keep fanotify as **fallback** for kernels < 5.11.

**Why not BPF-LSM from day one?**
- Requires kernel ≥ 5.11 for sleepable programs (the synchronous blocking requirement)
- `vmlinux.h` BTF dependency — needs `CONFIG_DEBUG_INFO_BTF=y`
- Significantly higher implementation complexity
- Not worth the complexity for an MVP that needs to prove the concept first

---

## What a Traditional Kernel Module Would Add

A traditional `.ko` LSM module (like a stripped-down SELinux) would allow:
- Custom `task_struct` blob fields for Zelx metadata (slightly faster lookup)
- Hooks not exposed via BPF-LSM (very few in practice)
- Kernel version-independent operation (ship as DKMS)

**Why we don't need it:**
BPF-LSM (Phase 5) covers all the hooks Zelx needs. The only advantage of a `.ko`
is marginally faster task metadata access, which is not worth:
- Matching kernel headers per distro/version
- Secure Boot signing requirements
- DKMS rebuild on every kernel update
- Barrier to contribution (requires kernel build environment)

**Verdict: BPF-LSM is sufficient. No `.ko` module.**

---

## Kernel Version Requirements Per Phase

| Phase | Minimum Kernel | Config Flags Required |
|---|---|---|
| Phase 0–3 | 3.8 | None (fanotify is always available) |
| Phase 4 | 5.0 | None (seccomp_unotify is mainline) |
| Phase 5 | 5.7 (BPF-LSM) | `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` |
| Phase 5 (sync) | 5.11 (sleepable BPF) | Same as above + `CONFIG_BPF_EVENTS=y` |
| Phase 6 | 5.0 (user namespaces) | `CONFIG_USER_NS=y` (default on most distros) |

Most modern distros (Arch, Fedora 39+, Ubuntu 24.04+) ship kernels ≥ 6.x with
all required configs enabled.
