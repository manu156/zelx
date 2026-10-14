# Phase 2 — App Identity via cgroup v2

**Status:** `[ ] Not started`
**Depends on:** Phase 1
**Goal:** Stable, unspoofable app identity that survives child processes.

---

## The Problem This Solves

In Phases 0–1, identity = PID. This breaks in the real world:

```
zelx-run kitty
  └─ kitty (PID 1000)  ← policy bucket "kitty"
       └─ zsh (PID 1001)  ← NEW policy bucket "zsh" — WRONG
            └─ nvim (PID 1002)  ← NEW policy bucket "nvim" — WRONG
                 └─ git (PID 1003)  ← NEW policy bucket "git" — WRONG
```

Every child process generates separate prompts. `git` asks permission to read
your home directory. This is unusable.

The fix: **every process in the same app launch shares one cgroup slice**.
cgroup membership is inherited by `fork()` and cannot be changed without
`CAP_SYS_ADMIN`.

---

## cgroup v2 Identity Model

### App slice creation (in `zelx-run`)

```bash
# zelx-run creates a transient scope under zelx.slice
APP_ID="${1##*/}-$(uuidgen | cut -c1-8)"
CGROUP_PATH="/sys/fs/cgroup/zelx.slice/zelx-${APP_ID}.scope"

mkdir -p "$CGROUP_PATH"
echo $$ > "$CGROUP_PATH/cgroup.procs"   # move self into it

# Now exec the app — it inherits this cgroup
exec "$@"
```

All children of this process (and their children) automatically live in
`zelx-${APP_ID}.scope`. The cgroup path is the stable identity.

### Identity lookup in `zelxd`

```c
// identity.c
char *zelx_get_app_id(pid_t pid) {
    // Read /proc/<pid>/cgroup
    // Find the line: 0::/zelx.slice/zelx-<app>-<uuid>.scope
    // Return "zelx-discord-a3f2b1c8" (stable for all children)
}
```

### Policy stored by app base name

Strip the UUID for policy storage:
- cgroup: `zelx-discord-a3f2b1c8.scope`
- Policy key: `discord`

Different launches of the same app share the same policy rules.
The UUID exists only for process accounting and audit trail.

---

## systemd Integration (Alternative)

Instead of manual cgroup manipulation, use `systemd-run`:

```bash
systemd-run --user --scope \
  --slice=zelx.slice \
  --unit="zelx-discord-$(uuidgen | cut -c1-8)" \
  --property=Delegate=yes \
  discord
```

This is cleaner but requires a running `systemd --user` session.
Provide both: `--systemd` flag uses `systemd-run`, default uses raw cgroup.

---

## Terminal App Handling

See [RFC-003](../rfc/RFC-003-terminal-heuristic.md) for the full design.

Short version: terminal emulators (`kitty`, `foot`, `alacritty`, `wezterm`)
get a **shell policy bucket** that is more permissive than a GUI app bucket.
The cgroup slice is still `zelx-kitty-<uuid>`, and all shells/editors inside
it share the `kitty` policy.

---

## `zelxctl` Identity Subcommands

```bash
zelxctl apps                              # list all active zelx cgroup scopes
zelxctl apps --all                        # include dead/exited scopes
zelxctl trace discord --pid 4821          # filter by specific launch instance
```

---

## Success Criteria

- [ ] `zelx-run kitty` → open `nvim` inside → `git commit` triggers no new prompts
  (git inherits kitty's cgroup and thus kitty's policy)
- [ ] `zelx-run discord` and `zelx-run firefox` have completely separate policy buckets
- [ ] Two concurrent `zelx-run discord` instances have separate audit entries but
  share the same policy rules
- [ ] Killing `zelx-run` kills the entire cgroup (all children) cleanly
- [ ] `zelxctl apps` shows `discord-a3f2b1c8` and `firefox-99de1a23` as separate

---

## Known Limitations in This Phase

- `zelx-run` must be the parent — apps launched outside it have no Zelx identity
- Terminal emulator heuristic for policy buckets is still configuration-based
- Network access still not intercepted
- No Wayland overlay — prompt is still CLI
