# Zelx Architecture

## Goal

Run native Linux binaries on a host Wayland desktop with **zero implicit trust** —
the same security guarantees Android gives to app processes, without containers,
Flatpak, or Snap.

---

## Security Model in One Sentence

> Every process launched through Zelx starts with read-only access to system
> libraries and nothing else. All other resource access — files, network, devices,
> IPC — requires an explicit user grant that is permanently audited.

---

## Current implementation and language

Phases 0–1 use Rust for `zelxd`, `zelxctl`, and `zelx-run`, with a shared library.
The reader owns kernel descriptors and deadlines; a worker owns SQLite, session
rules, caching, and prompts. Channels connect them. Linux ABI operations are
isolated behind documented safe wrappers. See [RFC-005](./rfc/RFC-005-rust-runtime.md)
and the [runtime guide](./runtime.md).

The rest of this document describes the target architecture across all phases.
The current launcher sets an informational identity hint; cgroup identity,
Wayland, network/media policy, and isolation remain future work.

## The Four Pillars

| Pillar | Android Equivalent | Zelx Mechanism |
|---|---|---|
| **Identity** | UID per app | Privileged launch registry plus protected cgroup v2 membership |
| **Default-Deny Policy** | SELinux MAC | BPF-LSM hooks (Phase 5) / fanotify (Phase 0) |
| **Runtime Permissions** | `PackageManager` + dialog | `zelxd` policy engine + `zelx-overlay` |
| **Auditability** | `logcat` / Privacy Dashboard | SQLite append-only audit log + `zelxctl` |

---

## Component Map

```
┌──────────────────────────────────────────────────────────────────────┐
│  USER SPACE                                                          │
│                                                                      │
│  ┌─────────────┐   Unix socket   ┌──────────────────────────────┐   │
│  │zelx-overlay │◄───────────────►│                              │   │
│  │(wlr-layer-  │  permission req  │         z e l x d           │   │
│  │ shell UI)   │  allow/deny resp │                              │   │
│  └─────────────┘                 │  ┌──────────┐  ┌──────────┐  │   │
│                                  │  │  Policy  │  │  Audit   │  │   │
│  ┌─────────────┐                 │  │  Engine  │  │  Writer  │  │   │
│  │  zelxctl    │◄── SQLite ──────│  └──────────┘  └────┬─────┘  │   │
│  │  (CLI/TUI)  │                 │                     │        │   │
│  └─────────────┘                 └─────────────────────┼────────┘   │
│                                                         │            │
│  ┌─────────────┐                                        │            │
│  │  zelx-wire  │  (PipeWire / WirePlumber broker)       │ SQLite     │
│  │  mic / cam  │                                        │            │
│  └─────────────┘                                   zelx.db          │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│  KERNEL APIs  (no .ko module required)                               │
│                                                                      │
│  fanotify FAN_OPEN_PERM   →  filesystem interception (Phase 0)      │
│  seccomp_unotify          →  syscall supervisor (Phase 4)           │
│  BPF-LSM (libbpf)         →  deep security hooks (Phase 5)          │
│  cgroup v2                →  app identity + resource accounting      │
│  namespaces (user/mnt/net)→  hard isolation boundary (Phase 6)      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Component Responsibilities

### `zelxd` — Core Policy & Audit Daemon

The central authority. Runs as a privileged service (root or `CAP_SYS_ADMIN`).

- **Identity resolution**: Maps events to a verified instance in a privileged cgroup registry; names and cgroup paths alone do not authenticate apps (Phase 2)
- **Policy evaluation**: Checks saved rules; if no rule, initiates a permission request
- **Prompt dispatch**: Forwards permission requests to `zelx-overlay` (Wayland) or CLI
- **Audit writing**: Appends every decision (allow/deny/prompt) to SQLite with timestamps
- **Exemption list**: Never intercepts its own PID, `zelx-overlay`, or the Wayland compositor

### `zelx-overlay` — Wayland Permission UI

A dedicated Wayland client using `wlr-layer-shell`.

- Renders always-on-top, input-exclusive permission dialogs (clickjack-proof)
- Communicates with `zelxd` via a Unix domain socket
- Shows: app identity, resource type, exact path/address, previous decision history
- User response: **Allow Once / Allow Session / Allow Always / Deny Once / Deny Always**

### `zelxctl` — CLI / TUI Dashboard

The user-facing audit and policy management tool.

```bash
zelxctl trace discord --last 1h          # audit trail for an app
zelxctl policy list firefox              # show all saved rules for firefox
zelxctl policy revoke discord network    # remove network permission
zelxctl monitor                          # live event stream (TUI)
```

### `zelx-run` — App Launcher

Wraps an app launch to establish its Zelx identity before `exec()`.

1. Creates a transient `cgroup v2` slice: `/sys/fs/cgroup/zelx/<app>-<uuid>/`
2. Moves the process into it
3. Applies `seccomp` filter (Phase 4+)
4. Sets up namespace boundaries (Phase 6)
5. `exec()`s the target binary

### `zelx-wire` — Media & IPC Broker

A WirePlumber plugin / PipeWire proxy.

- Gates microphone and camera access behind zelxd policy
- Intercepts `wp_security_context_v1` and `SO_PEERCRED` on Hyprland IPC
- Translates media access into zelxd permission requests

---

## Data Flow: File Access Permission

```
App: open("/home/user/.ssh/id_rsa")
         │
         ▼
[kernel fanotify / BPF-LSM hook]
         │  FAN_OPEN_PERM event (PID, path)
         ▼
    zelxd receives event
         │
         ├─ verify process membership → privileged instance registry → app policy
         ├─ lookup policy DB: no rule for (discord, ~/.ssh/**)
         │
         ▼
    zelxd → Unix socket → zelx-overlay
         │                    │
         │                    ▼
         │            [Wayland dialog shown]
         │            "Discord wants to read ~/.ssh/id_rsa"
         │            [User clicks DENY ALWAYS]
         │                    │
         ◄────────────────────┘  deny response
         │
         ├─ write rule: (discord, ~/.ssh/**, DENY_ALWAYS) → SQLite
         ├─ write audit: (discord, open, ~/.ssh/id_rsa, DENY, ts) → SQLite
         │
         ▼
    zelxd → FAN_DENY → kernel
         │
         ▼
App: open() returns EPERM (fanotify FAN_DENY)
```

---

## Default Allow-list (System Paths)

These are auto-allowed for all apps without prompting:

```
/usr/**
/lib/**
/lib64/**
/etc/ld.so.*
/etc/fonts/**
/etc/locale*
/etc/timezone
/etc/ssl/certs/**
/proc/self/**
/sys/class/dri/**          (GPU, read-only)
/run/user/<uid>/wayland-*  (Wayland socket - gated separately)
/tmp/**                    (phase 0 only, tightened later)
```

Everything under `$HOME`, `/run/user/<uid>/` (except Wayland), `/dev/**`, and
network addresses requires explicit permission.

---

## Non-Goals

See [Threat Model](./threat-model.md) for the full list. In short:

- Zelx is **not** a replacement for a firewall — it complements one
- Zelx is **not** designed to stop a root process or `CAP_SYS_ADMIN` process
- Zelx is **not** a container runtime — processes run on the host
- Zelx does **not** protect against hardware exploits or firmware attacks
- Zelx does **not** currently support X11 (Wayland-only, starting with Hyprland)
