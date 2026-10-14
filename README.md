# Zelx

**Zero-trust runtime permissions and real-time syscall auditing for native Linux & Wayland.**

Zelx brings Android’s runtime permission model and privacy dashboard directly to the Linux kernel and Wayland compositors (starting with **Hyprland**) — **without containers, Flatpaks, or Bubblewrap.**

---

## The Problem

Desktop Linux still relies on 1970s Discretionary Access Control (DAC). Every program you launch under your user session inherits your `UID` and full authority over your digital life:

- Any game, script, or Electron app can silently read `~/.ssh`, `~/Documents`, or browser cookies.
- Container workarounds (`Flatpak`, `Bubblewrap`, `Snap`) duplicate runtimes, break native CLI workflows, and rely on `xdg-desktop-portal` APIs that only work if the application chooses to cooperate.
- Compositor-level permission flags (such as Hyprland's `enforce_permissions`) guard Wayland protocols like `screencopy`, but cannot stop an unsandboxed process from reading files, opening network sockets, or talking to raw IPC sockets.

## The Vision

**Run native binaries directly on your host OS, with zero implicit trust.**

When an application launches under **Zelx**, it starts with access only to standard read-only system libraries (`/usr`, `/lib`, fonts). The moment it attempts to access personal directories, hardware streams, or external networks:

1. **Freeze:** The kernel synchronously pauses the calling thread mid-syscall before any data is read.
2. **Prompt:** A tamper-proof Wayland compositor overlay (`wlr-layer-shell`) asks you to **Allow** or **Deny** (Once, Session, or Forever).
3. **Audit:** Every file open, microphone/camera stream, and network connection is recorded with millisecond timestamps so you can inspect exactly what an app used and when.

```text
$ zelxctl trace discord --last 1h
TIMESTAMP            DECISION   RESOURCE      TARGET                               DURATION
2026-10-14 16:41:02  ALLOW      microphone    PipeWire: alsa_input.pci-0000_00_1f  14m 22s
2026-10-14 16:40:58  DENY       filesystem    /home/user/.ssh/id_ed25519           -
2026-10-14 16:40:12  ALLOW      network       162.159.135.232:443 (discord.gg)     active

Architecture
Zelx operates across four native layers of the Linux stack:
| Component | Layer | Responsibility |
|---|---|---|
| zelx-lsm / Kernel Hooks | Kernel (fanotify + BPF-LSM) | Intercepts security_file_open, security_socket_connect, and openat calls synchronously without VFS deadlocks. |
| zelxd | Core Policy & Audit Daemon | Tracks un-spoofable app identity via cgroup v2 slices and LSM task blobs, evaluates saved policy rules, and writes eBPF ringbuffer telemetry to SQLite. |
| zelx-wire | Media & IPC Broker | Hooks into PipeWire / WirePlumber and Hyprland IPC (wp_security_context_v1 / SO_PEERCRED) to gate microphone, camera, and compositor control. |
| zelx-overlay & zelxctl | Wayland UI & CLI | Renders clickjack-proof permission prompts on the Wayland overlay layer and provides a CLI/TUI privacy dashboard. |
Core Engineering Challenges
We are tackling three foundational problems in desktop Linux security:
 * Deadlock-Free Synchronous Upcalls: Pausing a process on filesystem access before kernel VFS inode locks (i_rwsem) are held, and exempting the compositor/daemon path so the UI never freezes.
 * The POSIX Process Tree Problem: Distinguishing interactive GUI applications from terminal multiplexers (kitty -> zsh -> nvim -> git) using scoped session labels so developers aren't spammed by CLI popups while untrusted scripts remain contained.
 * Zero-Config Baseline Profiles: Automatically permitting benign runtime reads (/usr/lib, shader caches, locale data) while strictly gating $HOME, credentials, devices, and sockets.
Roadmap
 * [x] Phase 1 (MVP): Synchronous directory protection, process freezing, Wayland prompt, and live audit logging via fanotify (FAN_OPEN_PERM).
 * [ ] Phase 2 (Identity & UI): Track child processes via cgroup v2 app slices and replace generic dialogs with a native wlr-layer-shell Hyprland overlay.
 * [ ] Phase 3 (Deep Hooks): Sleepable BPF-LSM (BPF_PROG_TYPE_LSM) for network sockets and recursive path policies + WirePlumber plugin for microphone/camera gating.
 * [ ] Phase 4 (Compositor Integration): Native Hyprland plugin/patches to lock hyprctl IPC sockets and clipboard access behind zelxd policies.
Contributing
Zelx is looking for collaborators who want to fix desktop Linux security at the root. We especially welcome:
 * Kernel & eBPF Engineers: BPF-LSM, fanotify, seccomp_unotify, and custom LSM development.
 * Wayland / Hyprland Developers: wlr-layer-shell, input locking, and C++ Hyprland plugin integration.
 * Systems Programmers (C / Rust): High-performance daemon (zelxd) and SQLite/eBPF audit pipeline.
Open an issue or join the discussion to claim a module.

<ElicitationsGroup message="What should we build next for the Zelx repository?">
  <Elicitation label="Upgrade the MVP code to match Zelx naming" query="Refactor the C MVP code into clean zelxd and zelxctl files with SQLite audit logging so I can make my initial Git commit."/>
  <Elicitation label="Build the native Hyprland overlay prompt" query="Write the zelx-overlay Wayland layer-shell prompt so it renders natively over Hyprland and talks to zelxd via a Unix socket."/>
  <Elicitation label="Design the CLI vs GUI permission model" query="Design the exact rule and cgroup model for how Zelx handles terminal apps (like kitty running bash/nvim) versus standalone GUI apps."/>
</ElicitationsGroup>
```
