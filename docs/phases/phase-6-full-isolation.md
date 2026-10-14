# Phase 6 — Full Process Isolation (Namespace Sandboxing)

**Status:** `[ ] Not started`
**Depends on:** Phase 5
**Goal:** Android-equivalent process isolation — apps literally cannot see resources they haven't been granted.

---

## Objective

Phases 0–5 intercept access attempts and allow/deny them. This is **interception-based security** — the app can still *try* to access anything; Zelx just blocks the attempt.

Phase 6 moves to **isolation-based security** — the app can't even see resources it hasn't been granted. It's like Android's per-app UID + private data directory model: the app has its own view of the filesystem, network stack, and process table.

This is achieved via **Linux namespaces** combined with the permission model from earlier phases.

---

## Namespace Isolation Model

Each `zelx-run`-launched app gets its own:

| Namespace | What it isolates | Effect |
|---|---|---|
| **mount (`mnt`)** | Filesystem view | App sees only `/usr`, `/lib`, and granted paths |
| **network (`net`)** | Network stack | App has no network by default; granted per-destination |
| **PID (`pid`)** | Process visibility | App cannot see other user processes |
| **user (`user`)** | UID/GID mapping | App thinks it's root inside its namespace |
| **IPC (`ipc`)** | SysV IPC, POSIX MQ | App cannot access shared memory of other apps |

**NOT isolated** (intentionally):
- UTS (hostname) — not needed
- Time — not needed, and dangerous to isolate

---

## Mount Namespace: The Filesystem View

```
Host filesystem                   App's filesystem view (Discord)
/                                 /
├── usr/ ────────────────────►    ├── usr/   (bind-mount, read-only)
├── lib/ ────────────────────►    ├── lib/   (bind-mount, read-only)
├── etc/fonts/ ──────────────►    ├── etc/fonts/ (bind-mount, read-only)
├── home/user/                    ├── home/user/
│   ├── .ssh/         ✗ (no grant)│   │   (not mounted — invisible)
│   ├── .config/discord/ ───────► │   ├── .config/discord/ (bind-mount, rw)
│   └── Downloads/ ─────────────► │   └── Downloads/ (bind-mount, ro or rw)
├── proc/ ───────────────────►    ├── proc/  (new pidns proc — only self visible)
├── dev/                          ├── dev/
│   ├── null ───────────────►     │   ├── null   (always present)
│   ├── urandom ────────────►     │   ├── urandom
│   └── snd/ ✗ (no grant)         │   (audio devices absent unless granted)
└── run/user/1000/                └── run/user/1000/
    ├── wayland-0 ──────────►         ├── wayland-0  (Wayland socket — always)
    └── pipewire-0 ──────────►        └── pipewire-0 (PipeWire — gated in phase 5)
```

### Building the mount namespace

```c
// zelx-run Phase 6 (simplified)
unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWIPC);

// Set up UID mapping (app appears as uid=1000 inside its own namespace)
// write "0 1000 1" to /proc/self/uid_map and gid_map

// Mount the base system (read-only)
mount("/usr",       "/zelx-root/usr",       MS_BIND | MS_REC | MS_RDONLY);
mount("/lib",       "/zelx-root/lib",       MS_BIND | MS_REC | MS_RDONLY);
mount("/etc/fonts", "/zelx-root/etc/fonts", MS_BIND | MS_REC | MS_RDONLY);

// Mount granted paths (from policy database)
for each granted_path in zelxd_get_grants(app_id):
    flags = granted_path.writable ? MS_BIND : MS_BIND | MS_RDONLY;
    mount(granted_path.real, zelx_root + granted_path.virt, flags);

// Pivot root into the new namespace
pivot_root("/zelx-root", "/zelx-root/.old-root");
umount2("/.old-root", MNT_DETACH);

exec(app);
```

### Dynamic mount grants (post-launch)

When the user grants a new path permission after launch, `zelxd` signals
`zelx-run`'s mount namespace manager to bind-mount the new path into the
running namespace. This uses `/proc/<pid>/ns/mnt` + `nsenter`.

---

## Network Namespace Isolation

Each app gets its own network namespace with:
- A `veth` pair connecting to a `zelx-bridge` managed by `zelxd`
- No routes by default (no network access)
- `zelxd` adds routing rules when network permission is granted

```
App netns: veth-app ──── veth-host ──── zelx-bridge ──── iptables NAT ──── Host network
                         (in host ns)
```

When the user denies a network connection:
- `zelxd` adds an `iptables` DROP rule for that destination
- More reliable than seccomp_unotify for already-granted-then-revoked connections

When the user grants "discord.com:443":
- `zelxd` adds a DNAT rule allowing only that destination/port
- All other outbound traffic is dropped by default policy

---

## Capabilities

Apps are launched with an empty capability set:

```c
// Drop all capabilities before exec()
cap_t caps = cap_init();  // empty set
cap_set_proc(caps);
cap_free(caps);
```

Capabilities are granted per-permission:
- Microphone/camera → no cap needed (PipeWire socket access)
- Listen on port < 1024 → `CAP_NET_BIND_SERVICE` (rarely granted)
- Raw network → `CAP_NET_RAW` (rarely granted, requires explicit user approval)

---

## Interaction with BPF-LSM (Phase 5)

In Phase 6, BPF-LSM becomes a **defense-in-depth second layer**, not the
primary enforcement mechanism. The mount namespace is the first line:

```
App tries: open("/home/user/.ssh/id_rsa")
    ↓
Mount namespace: that path doesn't exist in the app's view → ENOENT (immediate)
    ↓
BPF-LSM: (never reached — namespace prevented it)
```

BPF-LSM remains essential for:
- Protecting against namespace escape attempts
- Network-level policy (separate netns handles routing, BPF-LSM handles edge cases)
- Audit logging (BPF ring buffer is still the source of truth)

---

## `zelx-run` Final Form

```
zelx-run <app> [args...]
    1. Create cgroup v2 slice (Phase 2)
    2. Apply seccomp filter (Phase 4)
    3. Unshare namespaces (Phase 6)
    4. Set up UID mapping (Phase 6)
    5. Build mount namespace from policy grants (Phase 6)
    6. Set up network namespace + veth pair (Phase 6)
    7. Drop capabilities (Phase 6)
    8. exec(app)
```

---

## Success Criteria

- [ ] Discord cannot see `/home/user/.ssh/` at all (ENOENT, not EACCES)
- [ ] Discord cannot see other user processes in `/proc/`
- [ ] Discord cannot reach the network without a grant
- [ ] A granted path (`~/.config/discord`) is readable/writable inside the app
- [ ] Revoking a path permission (zelxctl policy revoke) unmounts it from the live namespace
- [ ] App crashes/exits cleanly — no zombie mounts or dangling veth pairs
- [ ] `zelxctl trace discord` still shows the full audit trail

---

## Security Properties at This Phase

| Property | Mechanism | Guarantee |
|---|---|---|
| Filesystem confidentiality | Mount namespace | App cannot open paths not bind-mounted |
| Process isolation | PID namespace | App cannot see or signal other processes |
| Network isolation | Network namespace + iptables | App cannot reach hosts not explicitly allowed |
| IPC isolation | IPC namespace | App cannot access other apps' shared memory |
| Capability restriction | `cap_set_proc` | App cannot acquire elevated privileges |
| Defense-in-depth | BPF-LSM | Even if namespace is escaped, LSM blocks access |

This is the **Android security model on native Linux**. No containers. No Flatpak.
