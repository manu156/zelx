# Phase 5 — BPF-LSM Deep Hooks

**Status:** `[ ] Not started`
**Depends on:** Phase 4
**Goal:** Replace fanotify with BPF-LSM for deeper, lower-overhead security hooks.

---

## Objective

`fanotify` has fundamental limitations:
- Only covers `open()` — not `openat2()` variants in all cases
- Cannot intercept `socket()` at creation time (only `connect()` via seccomp)
- Cannot intercept `kill()` for process isolation
- Cannot intercept IPC (D-Bus, PipeWire, Binder-equivalent)

**BPF-LSM** (Linux Security Module via eBPF, kernel 5.7+) attaches programs to
LSM hook points — the same hooks SELinux and AppArmor use — but as eBPF bytecode
loaded at runtime via `libbpf`. No kernel module. No reboot.

This phase replaces the fanotify loop with BPF-LSM programs for file access, and
adds socket-level and process-level interception.

---

## New LSM Hook Points

| Hook | syscall intercepted | New capability |
|---|---|---|
| `security_file_open` | `open()`, `openat()`, all variants | Replace fanotify (more complete) |
| `security_socket_connect` | `connect()` | Replace seccomp hook for network |
| `security_socket_create` | `socket()` | Block raw socket creation |
| `security_task_kill` | `kill()`, `tgkill()` | Process isolation (stop signal injection) |
| `security_inode_rename` | `rename()` | Audit file moves |
| `security_ptrace_access_check` | `ptrace()` | Block debug-attach to other apps |

---

## BPF-LSM Architecture

The user-space loader remains Rust (RFC-005); the C below is a kernel BPF
program sketch, not a return to C for the daemon.

### eBPF program structure

```c
// zelx_lsm.bpf.c — loaded by zelxd via libbpf
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Ring buffer for events to zelxd userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

// Map of exempted cgroup IDs (zelxd, overlay, compositor)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);    // cgroup id
    __type(value, u8);   // 1 = exempt
} exempt_cgroups SEC(".maps");

// Map of cached policy decisions (hot path cache)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct policy_key);    // {cgroup_id, path_hash}
    __type(value, u8);                 // ALLOW=1, DENY=0
} policy_cache SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(zelx_file_open, struct file *file, int mask) {
    u64 cgid = bpf_get_current_cgroup_id();

    // Check exemptions
    if (bpf_map_lookup_elem(&exempt_cgroups, &cgid))
        return 0;  // allow

    // Check policy cache (fast path)
    // ...

    // Send event to userspace ring buffer for slow path (prompt)
    struct zelx_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = ZELX_EVENT_FILE_OPEN;
        e->cgroup_id = cgid;
        e->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_probe_read_kernel_str(e->path, sizeof(e->path),
                                  file->f_path.dentry->d_name.name);
        bpf_ringbuf_submit(e, 0);
    }

    // Block until zelxd updates the policy cache
    // (Sleepable BPF: BPF_F_SLEEPABLE — requires kernel 5.11+)
    return zelx_wait_for_decision(cgid, file);
}
```

### Sleepable BPF for synchronous blocking

`BPF_F_SLEEPABLE` programs (kernel 5.11+) can sleep and wait for a condition.
This allows the BPF program itself to block the syscall while zelxd processes
the request — cleaner than the fanotify fd approach.

If sleepable BPF is unavailable, fall back to: return `0` (allow) and log the
event; `zelxd` uses the policy cache for the next access to the same path.
(One-open gap — acceptable in the BPF path because the cache miss window is tiny.)

---

## PipeWire / WirePlumber Integration (zelx-wire)

Microphone and camera access goes through PipeWire, not via `open()` on a device
node. Gate it with a WirePlumber script plugin:

```lua
-- zelx-wire.lua (WirePlumber Lua plugin)
-- Intercepts all node link requests to audio/video source nodes
-- Sends a D-Bus message to zelxd before approving the link

local zelxd = require("zelxd")

SimpleEventHook {
  name = "zelx-wire/check-link",
  interests = { EventInterest { Constraint { "event.type", "=", "create-link" } } },
  execute = function(event)
    local target = event:get_subject()
    local client_node = target:get_connected_peer()
    local cgroup = client_node:get_property("application.process.cgroup")

    if not zelxd.check_permission(cgroup, "microphone", target:get_name()) then
      event:set_step_code(Si.StepCode.None)  -- reject the link
    end
  end
}:register()
```

---

## Performance Comparison

| Mechanism | Overhead per syscall | Limitations |
|---|---|---|
| `fanotify FAN_OPEN_PERM` | ~50–200µs (round-trip to userspace) | File open only |
| `seccomp_unotify` | ~100–300µs | Manual arg parsing |
| `BPF-LSM` (policy cache hit) | ~1–5µs (in-kernel) | Requires kernel 5.7+ |
| `BPF-LSM` (cache miss → prompt) | ~50–200ms (user prompt) | — |

The BPF policy cache means **repeated accesses to already-decided paths are
essentially free**. Only new/uncached paths pay the round-trip cost.

---

## Transition from fanotify

Phase 5 replaces the Phase 0 fanotify loop:
1. Load BPF-LSM programs via `libbpf` at `zelxd` startup
2. Read ring buffer events instead of `fanotify` fd events
3. Keep fanotify as a **fallback** if kernel < 5.11 (no sleepable BPF)

The policy engine and SQLite audit code are unchanged.

---

## Success Criteria

- [ ] BPF-LSM program loads without errors on kernel 5.11+
- [ ] File access interception is functionally equivalent to Phase 0–3 behavior
- [ ] `security_task_kill` hook prevents `kill -9` from one zelx app to another
- [ ] Microphone grant/deny works via WirePlumber plugin
- [ ] Policy cache measurably reduces repeat-access overhead (benchmark)
- [ ] Graceful fallback to fanotify on older kernels

---

## Requirements

- Linux kernel ≥ 5.11 (sleepable BPF-LSM) — or 5.7 for non-sleepable
- `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` in kernel config
- `libbpf` ≥ 0.8
- WirePlumber ≥ 0.4 (Lua scripting API)
