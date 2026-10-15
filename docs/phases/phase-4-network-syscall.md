# Phase 4 — Network & Syscall Interception (seccomp_unotify)

**Status:** `[ ] Not started`
**Depends on:** Phase 3
**Goal:** Gate network connections and other sensitive syscalls behind permissions.

---

## Objective

`fanotify` only covers filesystem access. Network connections, raw socket
creation, process signaling, and other sensitive syscalls require a different
mechanism: **`seccomp_unotify`** (Linux 5.0+).

`seccomp_unotify` installs a `seccomp` filter that, instead of killing the
process on a matching syscall, sends a notification to a supervising userspace
process — which can inspect arguments, make a decision, and either allow or
spoof the return value.

---

## New Permissions Gated in This Phase

| Permission | Syscall(s) intercepted | What user sees |
|---|---|---|
| **Network: outbound** | `connect()` | "Discord wants to connect to discord.com:443" |
| **Network: listen** | `bind()` | "App wants to listen on port 8080" |
| **Network: raw** | `socket(AF_PACKET, ...)` | "App wants raw network access" |
| **Clipboard read** | Hyprland IPC `wl_data_device` | "App wants to read clipboard" |
| **Screen capture** | `wlr-screencopy` protocol | "App wants to capture your screen" |
| **Process signal** | `kill()`, `tgkill()` | "App wants to signal process X" |
| **Exec new binary** | `execve()` | "App wants to execute /usr/bin/curl" |

---

## seccomp_unotify Architecture

### Setup (in `zelx-run`, Phase 4+)

The C structure below illustrates the Linux ABI; production user-space code
will use Rust with an audited syscall boundary (RFC-005).

```c
// zelx-run installs a seccomp filter before exec()
// The filter sends notifications to zelxd for sensitive syscalls

struct sock_filter filter[] = {
    // Load syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    // Match connect(), bind(), socket(), kill(), execve()
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect,  0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    // ... more syscalls
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
```

`SECCOMP_RET_USER_NOTIF` freezes the process and sends a notification fd
to `zelxd` (passed via `SECCOMP_IOCTL_NOTIF_RECV`).

### Network address resolution in `zelxd`

When intercepting `connect()`:
1. Read `sockaddr` from the frozen process's memory via `pidfd_getfd()` + `process_vm_readv()`
2. Resolve IP → hostname via reverse DNS (best-effort)
3. Build human-readable string: `"discord.com:443 (162.159.135.232)"`
4. Issue permission request with resource type `"network"`

### Spoofing return values

For "deny": `zelxd` uses `SECCOMP_IOCTL_NOTIF_SEND` with `error = ECONNREFUSED`.
The app sees a clean connection refusal, not a crash.

---

## Clipboard & Screen Capture (Compositor-Level)

These cannot be intercepted via `seccomp` — they go through Wayland protocols.
Gate them via Hyprland IPC:

- `zelxd` registers as a Hyprland IPC listener
- When a client requests `wlr_data_control` (clipboard) or `wlr_screencopy`:
  - Hyprland notifies `zelxd` (via a custom Hyprland plugin — see Phase 4 plugin)
  - `zelxd` issues a permission prompt
  - `zelxd` responds allow/deny to the plugin
  - Plugin approves or rejects the protocol request

This requires a small C++ Hyprland plugin (~200 lines).

---

## Updated `zelxctl` for Network Audit

```bash
zelxctl trace discord --resource network
```

Output:
```
TIMESTAMP            APP       DECISION  RESOURCE  TARGET
2026-10-14 16:41:02  discord   ALLOW     network   discord.com:443 (162.159.135.232)
2026-10-14 16:41:05  discord   ALLOW     network   gateway.discord.gg:443
2026-10-14 16:40:58  discord   DENY      network   analytics.example.com:443
```

---

## DNS Logging

Intercept `getaddrinfo()` / `gethostbyname()` via `seccomp_unotify` on the
underlying `sendto()` to `/etc/resolv.conf`'s DNS socket. Log hostname lookups
even if the subsequent `connect()` is allowed.

This provides: *"Discord looked up analytics.example.com even though it didn't
connect to it"* — revealing intent.

---

## Success Criteria

- [ ] `zelx-run discord` triggers a network permission prompt on first `connect()`
- [ ] Denied connections return `ECONNREFUSED` to the app (not a crash)
- [ ] Allowed network connections are logged with hostname + IP
- [ ] Screen capture request via `wlr-screencopy` shows a permission dialog
- [ ] Clipboard read request shows a permission dialog
- [ ] `zelxctl trace discord --resource network` shows full network history

---

## Known Limitations in This Phase

- `seccomp` filter must be installed before `exec()` — apps not launched via
  `zelx-run` have no network interception
- DNS logging is heuristic-based; DoH (DNS over HTTPS) is not intercepted at DNS level
- IPv6 addresses may not resolve to hostnames in all cases
- Clipboard interception requires a Hyprland-specific plugin (not compositor-agnostic)
- BPF-LSM in Phase 5 will replace some seccomp hooks with more reliable kernel hooks
