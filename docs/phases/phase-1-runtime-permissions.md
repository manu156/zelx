# Phase 1 — Runtime Permissions (CLI Prompt)

**Status:** Rust implementation — baseline real-kernel regression suite passed;
manual desktop smoke checks below remain separate.
See the [runtime guide](../runtime.md) for usage, validation results, and limits.
**Depends on:** Phase 0
**Goal:** Block unauthorized access and ask the user before allowing.

---

## Objective

Transform `zelxd` from a passive observer into an **active gatekeeper**.
When an app touches a protected path:
1. Freeze the calling thread using `FAN_OPEN_PERM`
2. Present a permission prompt to the user (CLI/terminal for now)
3. Respond before the original deadline; persist SESSION/ALWAYS only if accepted
4. Append the actual outcome to the audit log after the kernel response

Phase 1 gates supported file opens in watched roots. Comm identity is still
spoofable; this is not yet a hard security boundary. See the runtime guide.

---

## New Capabilities

- Per-app, per-resource **policy rules** evaluated before allow/deny
- Rule scopes: `ONCE | SESSION | ALWAYS`
- Default-allow list for system paths (auto-allowed without prompt)
- CLI prompt via stderr (no Wayland yet — that is Phase 3)
- `zelxctl policy` subcommands for manual rule management

---

## Policy Engine Design

### Rule evaluation order

```
1. Is this zelxd's own PID?              → ALLOW (exemption)
2. Is compositor / overlay PID?          → ALLOW (exemption)  
3. Does path match system allowlist?     → ALLOW (silent)
4. Lookup rules table:
     App-specific exact/glob matches, then global rules; permanent + session
   → Evaluate patterns in Rust using RFC-002 precedence; apply the best match
5. No rule found → PROMPT
6. After prompt: save rule if scope = SESSION or ALWAYS
```

### System allowlist (compiled-in defaults)

```rust
const SYSTEM_DIRECTORIES: &[&str] = &[
    "/usr", "/lib", "/lib64", "/etc/fonts", "/etc/ssl/certs",
    "/proc/self", "/sys/class/dri",
];
// Directory comparisons respect component boundaries. Additional baseline paths:
// /etc/ld.so.*, /etc/locale*, /etc/timezone.
```

---

## CLI Prompt Format

When no rule is found, `zelxd` writes a prompt to a dedicated TTY or stderr:

```
┌─────────────────────────────────────────────────────────────┐
│  ZELX PERMISSION REQUEST                                    │
│                                                             │
│  App:      discord (PID 4821)                               │
│  Wants:    open filesystem                                  │
│  Path:     /home/user/.ssh/id_ed25519                       │
│                                                             │
│  [1] Allow once    [2] Allow always                         │
│  [3] Deny once     [4] Deny always    [5] Allow session     │
└─────────────────────────────────────────────────────────────┘
Choice: _
```

The prompt is **blocking** — the kernel has frozen the app's thread.
Timeout: 30 seconds → auto-deny.

---

## `zelxctl policy` Subcommands

```bash
zelxctl policy list                        # all saved rules
zelxctl policy list discord                # rules for discord only
zelxctl policy revoke discord filesystem   # remove all FS rules for discord
zelxctl policy add discord allow "/home/user/.config/discord/**" always
zelxctl policy export > zelx-policy.json   # backup
zelxctl policy import zelx-policy.json     # restore
```

---

## Success Criteria

- [ ] `zelx-run discord` triggers a prompt when Discord first reads `~/.config`
- [ ] Choosing "Allow always" prevents future prompts for that exact path
- [ ] Choosing "Deny" causes Discord's `open()` to return `EPERM` (fanotify `FAN_DENY`)
- [x] Session rules expire when `zelxd` restarts (simulated runtime test)
- [x] `zelxctl policy list discord` shows saved permanent rules (CLI tests)
- [ ] Auto-deny fires correctly on timeout (no frozen processes)
- [x] System paths (`/usr/**`, `/lib/**`) bypass prompts (policy tests)

---

## Known Limitations in This Phase

- Identity still PID-based (child processes are treated as separate apps)
- Prompt appears in the terminal zelxd was launched from — not user-friendly for GUI apps
- Network access still not intercepted
- No Wayland overlay — GUI apps with no terminal get no prompt (auto-deny by default)
- Glob matching is simple prefix/glob, not recursive policy inheritance
