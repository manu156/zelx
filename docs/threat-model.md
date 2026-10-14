# Zelx Threat Model

## Attacker Model

Zelx protects against **malicious or compromised native applications** running
under your user session. The attacker is code that:

- You downloaded and ran (game, script, Electron app, binary blob)
- Was injected into a trusted app via a supply-chain attack
- Is a legitimate app behaving beyond its advertised purpose (telemetry, data harvesting)

### What the attacker can do (before Zelx)

- Call any syscall available to a standard user process
- Read any file accessible to your UID: `~/.ssh`, `~/.gnupg`, browser profiles,
  credentials, documents
- Exfiltrate data over any network interface
- Enumerate all running processes via `/proc`
- Open arbitrary device nodes (`/dev/snd`, `/dev/video0`)
- Send signals to any process owned by your UID

### What Zelx prevents

| Attack | Mechanism |
|---|---|
| Silent credential theft (`~/.ssh/**`, `~/.gnupg/**`) | fanotify FAN_OPEN_PERM → deny |
| Cookie/session exfiltration (browser profile reads) | fanotify FAN_OPEN_PERM → deny |
| Microphone/camera surveillance | PipeWire broker (zelx-wire) |
| Arbitrary network exfiltration | seccomp_unotify on connect() (Phase 4) |
| Process enumeration via /proc | BPF-LSM on open("/proc/<pid>/") (Phase 5) |
| Signal injection to other user processes | BPF-LSM on security_task_kill (Phase 5) |
| Clipboard sniffing | Hyprland IPC gating (Phase 4) |
| Screen capture | wlr-screencopy gating via Hyprland plugin (Phase 4) |

---

## Trust Hierarchy

```
FULLY TRUSTED (exempt from interception)
  └── zelxd itself (daemon PID exempted)
  └── zelx-overlay (display path must never freeze)
  └── Hyprland / Wayland compositor
  └── systemd (PID 1, cgroup manager)

USER-CONFIGURED TRUST
  └── Terminal emulators (kitty, foot, alacritty) — see RFC-003
  └── System daemons started outside zelx-run

ZERO IMPLICIT TRUST (zelx-run launched apps)
  └── All apps launched via `zelx-run <app>`
  └── All children they spawn (same cgroup, same policy)
```

---

## Explicit Non-Goals

### 1. Root process attacks
A process running as root or with `CAP_SYS_ADMIN` can escape cgroups, unmount
filesystems, and bypass fanotify. Zelx assumes the system root is trusted.
**Mitigation**: run apps with least privilege; Zelx is a layer on top, not
a replacement for privilege separation.

### 2. Kernel exploits
If an app exploits a kernel vulnerability to gain elevated privileges, Zelx
cannot prevent the subsequent actions. Zelx reduces the attack surface
significantly but is not a kernel hardening tool.

### 3. Side-channel attacks
Zelx does not protect against timing attacks, cache side-channels (Spectre/Meltdown
variants), or other microarchitectural attacks.

### 4. Pre-grant data exfiltration
If a user grants network access to an app, Zelx cannot inspect the content of
that network traffic. It records *that* the connection happened, not *what* was sent.
(A future `zelx-wire`-style proxy could address this for specific protocols.)

### 5. X11 / Xwayland
Zelx targets Wayland compositors. Under X11, any app can read keystrokes and
screenshot any window. Zelx does not and cannot fix this — use a Wayland-native
session.

### 6. Hardware/firmware attacks
UEFI implants, NIC firmware, GPU firmware attacks are entirely out of scope.

### 7. Physical access
Zelx is a runtime permission system, not a disk encryption or physical security tool.

---

## Security Properties at Full Maturity (Phase 6)

When fully deployed, an app launched via `zelx-run` has the following guarantees:

| Property | Guarantee |
|---|---|
| **Filesystem confidentiality** | Cannot read `$HOME/**` without explicit per-path user grant |
| **Network confidentiality** | Cannot open any socket without per-destination user grant |
| **Process isolation** | Cannot see or signal other user processes |
| **Device isolation** | Cannot open microphone, camera, or GPU without grant |
| **IPC isolation** | Cannot speak to Hyprland IPC, D-Bus system services, or PipeWire without grant |
| **Audit completeness** | Every resource access (allowed or denied) is logged with millisecond timestamp and app identity |
| **Tamper resistance** | Audit log is append-only; app cannot write to zelxd's SQLite file |
| **Identity stability** | cgroup v2 slice is unforgeable; child processes inherit identity automatically |
