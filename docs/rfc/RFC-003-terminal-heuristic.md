# RFC-003 — The Terminal Problem: CLI Apps, Shells, and Session Labels

**Status:** `Draft — needs user input`

---

## Problem

Linux terminal workflows look like this:

```
zelx-run kitty
  └─ kitty (terminal emulator)
       └─ zsh (shell)
            ├─ nvim ~/.config/nvim/init.lua   ← legitimate developer action
            ├─ git commit                      ← needs to read ~/.gitconfig, ~/.ssh/
            └─ curl https://example.com       ← network access
```

If we treat every process by its cgroup (solved by Phase 2), all of the above
share the `kitty` policy bucket. But the user launched `kitty` as a general-purpose
terminal, not as "trust kitty with network access and SSH keys."

**The question is: what policy should terminal-launched processes have?**

---

## The Tension

| Approach | Description | Problem |
|---|---|---|
| **Strict** | Terminal apps get the same zero-trust policy as GUI apps | Developer is prompted on every `git` operation — unusable |
| **Permissive** | Terminal apps are auto-trusted | An untrusted script run in the terminal can exfiltrate data |
| **Scoped** | The user explicitly declares the terminal's trust level at launch | More control, but requires user awareness |

---

## Options

### Option A: Terminal Emulators Are Trusted by Default
**Not recommended.**
Telemetry-heavy scripts, accidental `curl | bash` installs, and malicious
packages could all exfiltrate data silently. Defeats the purpose of Zelx for
developer workflows.

### Option B: Interactive Sessions Are Trusted, Non-Interactive Are Not
Distinguish:
- `kitty` with an interactive shell → user is present → more permissive
- `kitty -e some-script.sh` → non-interactive → stricter policy

Detection: check if `stdin` is a TTY (`isatty(STDIN_FILENO)`).

**Problem:** `kitty -e bash -c "malicious-script"` still has a TTY. A determined
attacker can fake it.

### Option C: Explicit Trust Level at `zelx-run` Time (Recommended)
The user specifies trust scope at launch:

```bash
zelx-run --trust=developer kitty      # developer trust: SSH, git, ~/.config/**
zelx-run --trust=restricted discord   # zero trust (default)
zelx-run --trust=full alacritty       # full user trust (like no Zelx)
```

**Trust levels:**

| Level | Auto-allows | Requires prompt for |
|---|---|---|
| `restricted` (default) | `/usr/**`, `/lib/**` only | Everything in `$HOME`, network |
| `developer` | + `~/.gitconfig`, `~/.config/**`, `~/.local/**`, `~/.ssh/` (read-only) | Network, `~/.ssh/` writes, `/dev/**` |
| `full` | Everything (Zelx is audit-only) | Nothing |

### Option D: Per-Command Annotations (Future)
Tag specific commands as trusted:

```bash
zelxctl trust-command git "~/.gitconfig,~/.ssh/**:ro,network:git*"
```

When `zelxd` sees a `git` exec inside a zelx cgroup, it temporarily elevates
permissions for that invocation. Requires `execve` interception (Phase 4).

---

## Recommended Approach (for Phase 2)

1. Ship with three built-in trust levels: `restricted`, `developer`, `full`
2. `zelx-run` defaults to `restricted` for all apps
3. Users configure terminal emulators in `/etc/zelx/trust-labels.toml`:

```toml
[app_trust_defaults]
kitty = "developer"
alacritty = "developer"
foot = "developer"
wezterm = "developer"
discord = "restricted"
firefox = "restricted"
```

4. `developer` trust pre-populates the policy DB with allow rules for common
   developer paths on first launch (no prompts for normal `git`/`nvim` use)

5. The `developer` allowlist is user-editable:
   ```toml
   [developer_trust_allowlist]
   filesystem = [
     "~/.gitconfig",
     "~/.config/**",
     "~/.local/share/**",
     "~/.cache/**",
     "~/.ssh/**:readonly",   # SSH keys readable but not writable
   ]
   network = []              # still prompts for network
   ```

---

## The SSH Key Problem

SSH keys are a special case:
- Legitimate use: `git push` over SSH
- Malicious use: a script exfiltrating `~/.ssh/id_ed25519`

In `developer` trust:
- `~/.ssh/**` is readable (allows `git push`, `ssh` commands)
- But `zelxd` still **logs all SSH key reads** with full app identity
- If an unexpected binary reads SSH keys, it shows in `zelxctl trace`

This is the audit-trail backstop: even if an attack succeeds under `developer`
trust, you have a forensic record.

---

## Open Questions for the User

1. **Is the `developer` trust level the right default for terminal emulators?**
   Or should users explicitly opt in?

2. **Should network access always require a prompt, even in `developer` mode?**
   (Current recommendation: yes — network is the highest-risk permission)

3. **Should `zelx-run --trust=developer kitty` be the default, or should Zelx
   ship with terminal emulators pre-configured to `developer` in the system defaults?**

4. **How should we handle `sudo` inside a zelx cgroup?**
   `sudo` elevates to root, which bypasses all Zelx enforcement.
   Options: block `sudo` entirely, log it, or treat it as trust escalation that
   requires a Zelx overlay confirmation.
