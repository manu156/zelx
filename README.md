# Zelx

**Zero-trust runtime permissions and real-time syscall auditing for native Linux & Wayland.**

Zelx brings Android's runtime permission model and privacy dashboard directly to the Linux kernel and Wayland compositors (starting with **Hyprland**) — **without containers, Flatpaks, or Bubblewrap.**

> [!WARNING]
> **Alpha software.** Zelx is in early development. It is not yet suitable for production use.
> APIs, configuration formats, and on-disk schemas may change without notice between versions.

---

## Key Goals

| Goal | Description |
|---|---|
| **Security** | Default-deny. Every process starts with zero implicit trust. No resource is accessible without an explicit user grant. |
| **Performance** | Interception overhead must be imperceptible on the hot path. Policy cache hits target sub-5µs latency via BPF-LSM. |
| **Auditability** | Every access — allowed or denied — is logged with millisecond precision, app identity, and resource target. Nothing is silent. |
| **Isolation** | Apps are isolated from each other's files, processes, network, and IPC. Full namespace-based sandboxing is the end state. |

---

## The Problem

Desktop Linux still relies on 1970s Discretionary Access Control (DAC). Every program you launch under your user session inherits your `UID` and full authority over your digital life:

- Any game, script, or Electron app can silently read `~/.ssh`, `~/Documents`, or browser cookies.
- Container workarounds (`Flatpak`, `Bubblewrap`, `Snap`) duplicate runtimes, break native CLI workflows, and rely on `xdg-desktop-portal` APIs that only work if the application chooses to cooperate.
- Compositor-level permission flags (such as Hyprland's `enforce_permissions`) guard Wayland protocols like `screencopy`, but cannot stop an unsandboxed process from reading files, opening network sockets, or talking to raw IPC sockets.

---

## The Vision

**Run native binaries directly on your host OS, with zero implicit trust.**

When an application launches under **Zelx**, it starts with access only to standard read-only system libraries (`/usr`, `/lib`, fonts). The moment it attempts to access personal directories, hardware streams, or external networks:

1. **Freeze:** The kernel synchronously pauses the calling thread mid-syscall before any data is read.
2. **Prompt:** A tamper-proof Wayland compositor overlay (`wlr-layer-shell`) asks you to **Allow** or **Deny** (Once, Session, or Forever).
3. **Audit:** Every file open, microphone/camera stream, and network connection is recorded with millisecond timestamps so you can inspect exactly what an app used and when.

```
$ zelxctl trace discord --last 1h
TIMESTAMP            DECISION   RESOURCE      TARGET                               DURATION
2026-10-14 16:41:02  ALLOW      microphone    PipeWire: alsa_input.pci-0000_00_1f  14m 22s
2026-10-14 16:40:58  DENY       filesystem    /home/user/.ssh/id_ed25519           -
2026-10-14 16:40:12  ALLOW      network       162.159.135.232:443 (discord.gg)     active
```

---

## Architecture

Zelx operates across four native layers of the Linux stack:

| Component | Layer | Responsibility |
|---|---|---|
| **Kernel Hooks** | Kernel (`fanotify` + BPF-LSM) | Intercepts `security_file_open`, `security_socket_connect`, and `openat` calls synchronously without VFS deadlocks. |
| **`zelxd`** | Core Policy & Audit Daemon | Tracks unspoofable app identity via cgroup v2 slices, evaluates saved policy rules, and writes telemetry to SQLite. |
| **`zelx-wire`** | Media & IPC Broker | Hooks into PipeWire / WirePlumber and Hyprland IPC to gate microphone, camera, and compositor control. |
| **`zelx-overlay` & `zelxctl`** | Wayland UI & CLI | Renders clickjack-proof permission prompts on the Wayland overlay layer and provides a CLI/TUI privacy dashboard. |

See [`docs/architecture.md`](./docs/architecture.md) for the full component map and data flows.

---

## Core Engineering Challenges

- **Deadlock-Free Synchronous Upcalls:** Pausing a process on filesystem access before kernel VFS inode locks (`i_rwsem`) are held, and exempting the compositor/daemon path so the UI never freezes.
- **The POSIX Process Tree Problem:** Distinguishing interactive GUI applications from terminal multiplexers (`kitty` → `zsh` → `nvim` → `git`) using cgroup v2 scoped session labels so developers aren't spammed by popups while untrusted scripts remain contained.
- **Zero-Config Baseline Profiles:** Automatically permitting benign runtime reads (`/usr/lib`, shader caches, locale data) while strictly gating `$HOME`, credentials, devices, and sockets.

---

## Roadmap

- [x] **Phase 0 — fanotify Audit:** Synchronous filesystem interception and live audit logging.
- [ ] **Phase 1 — Runtime Permissions:** Policy engine with allow/deny rules and CLI prompts.
- [ ] **Phase 2 — App Identity:** Track child processes via cgroup v2 app slices.
- [ ] **Phase 3 — Wayland Overlay:** Native `wlr-layer-shell` Hyprland permission dialog.
- [ ] **Phase 4 — Network & Syscall:** `seccomp_unotify` for network, clipboard, and screen capture gating.
- [ ] **Phase 5 — BPF-LSM:** Sleepable `BPF_PROG_TYPE_LSM` for deep hooks + WirePlumber plugin.
- [ ] **Phase 6 — Full Isolation:** Namespace-based sandboxing (mount, net, pid, ipc) — Android-equivalent isolation.

See [`docs/phases/`](./docs/phases/) for detailed plans and success criteria for each phase.

---

## Documentation

| Document | Description |
|---|---|
| [`docs/architecture.md`](./docs/architecture.md) | Full system design and component map |
| [`docs/threat-model.md`](./docs/threat-model.md) | What Zelx protects against and explicit non-goals |
| [`docs/phases/`](./docs/phases/) | Per-phase implementation plans |
| [`docs/rfc/`](./docs/rfc/) | Design decisions and their rationale |

---

## Contributing

Zelx is looking for collaborators who want to fix desktop Linux security at the root. We especially welcome:

- **Kernel & eBPF Engineers:** BPF-LSM, fanotify, `seccomp_unotify`, and custom LSM development.
- **Wayland / Hyprland Developers:** `wlr-layer-shell`, input locking, and C++ Hyprland plugin integration.
- **Systems Programmers (C / Rust):** High-performance daemon (`zelxd`) and SQLite/eBPF audit pipeline.

Open an issue or join the discussion to claim a module.

---

## AI Disclosure

AI tools (large language models) were used to assist with writing code and documentation in this project.

All AI-generated code is reviewed and tested by human contributors before being merged. However, **no guarantee is made that the code is correct, complete, or robust** — particularly in the kernel-adjacent and security-critical components where correctness is paramount.

The goal of this project is **high-quality, well-reasoned systems code** — not a vibe-coded repository. If you find issues (logic errors, security flaws, incorrect assumptions), please open an issue. Rigorous review is actively encouraged and welcomed.
