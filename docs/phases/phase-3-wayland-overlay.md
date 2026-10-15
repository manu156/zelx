# Phase 3 — Wayland Permission Overlay

**Status:** `[ ] Not started`
**Depends on:** Phase 2
**Goal:** Replace CLI prompt with a native, clickjack-proof Wayland dialog.

---

## Objective

`zelx-overlay` is a dedicated Wayland client that renders permission dialogs
as a full-screen `wlr-layer-shell` surface — always on top, with keyboard and
pointer grab, impossible for other apps to obscure or spoof.

This is the phase where Zelx becomes **usable by non-technical users**.

---

## Architecture

```
zelxd  ──── Unix socket (/run/zelx/overlay.sock) ────  zelx-overlay
             (permission request JSON)                   (renders dialog)
             (allow/deny/scope response JSON)            (waits for click)
```

`zelx-overlay` is a **long-running process** (not spawned per-prompt) that
stays connected to `zelxd` and handles one prompt at a time.

---

## Protocol (Unix Socket, newline-delimited JSON)

### Request (zelxd → zelx-overlay)

```json
{
  "id": "req-0042",
  "app_id": "discord",
  "app_display_name": "Discord",
  "app_exe": "/opt/discord/Discord",
  "resource": "filesystem",
  "target": "/home/user/.ssh/id_ed25519",
  "previous_decisions": [
    { "target": "/home/user/.ssh/known_hosts", "decision": "DENY", "ts": 1728912062 }
  ]
}
```

### Response (zelx-overlay → zelxd)

```json
{
  "id": "req-0042",
  "decision": "DENY",
  "scope": "ALWAYS"
}
```

---

## Overlay Visual Design

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🔒  Permission Request                                 ║
║                                                          ║
║   Discord  wants to access:                              ║
║                                                          ║
║   📄  Filesystem                                         ║
║       /home/user/.ssh/id_ed25519                         ║
║                                                          ║
║   ─────────────────────────────────────────────          ║
║                                                          ║
║   [  Allow Once  ]  [  Allow Always  ]                   ║
║   [  Deny Once   ]  [  Deny Always   ]                   ║
║                                                          ║
║   ⏱  Auto-deny in 25s                                   ║
╚══════════════════════════════════════════════════════════╝
```

### Security properties of the overlay surface

- `wlr-layer-shell` layer: `ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY` (topmost)
- Exclusive keyboard zone: no other app receives key events during prompt
- Pointer grab: clicks outside the dialog do not reach other windows
- No app icon from the requesting app is rendered in the overlay process
  (prevents icon spoofing — the app cannot set its own icon)
- The compositor (Hyprland) must be configured to never allow other surfaces
  to occlude the `zelx-overlay` client

---

## `zelx-overlay` Implementation

Language: **Rust**, following [RFC-005](../rfc/RFC-005-rust-runtime.md).
Use Rust Wayland/protocol bindings and rendering libraries; native library
dependencies do not require writing the overlay itself in C.

Dependencies:
- `wayland-client`
- `wlr-layer-shell-unstable-v1` protocol
- `xdg-shell` (for popup positioning fallback)
- `cairo` + `pango` (text rendering)
- `libxkbcommon` (keyboard handling)

```rust
// Design sketch; protocol/rendering types will be chosen in Phase 3.
struct OverlayState {
    display: DisplayConnection,
    layer_surface: Option<LayerSurface>,
    current_request: Option<PermissionRequest>,
}
```

---

## Hyprland-Specific Configuration

Add to `hyprland.conf`:

```ini
# Prevent other windows from occluding zelx-overlay
layerrule = noanim, zelx-overlay
layerrule = dimaround, zelx-overlay

# Ensure overlay always gets input focus during prompts
# (handled automatically by exclusive input zone in wlr-layer-shell)
```

---

## Startup & Lifecycle

1. `zelxd` starts → waits for `zelx-overlay` to connect on the socket
2. `zelx-overlay` starts → connects to `zelxd` socket → connects to Wayland display
3. `zelxd` receives a permission event → sends JSON to overlay socket
4. `zelx-overlay` renders the surface, grabs input
5. User responds → overlay sends JSON back → releases input grab → hides surface
6. `zelxd` receives response → reader responds before deadline → worker persists
   an accepted grant and appends the actual audit outcome

If `zelx-overlay` crashes or disconnects: `zelxd` falls back to auto-deny with
a log entry: `"overlay unavailable — denied by default"`.

---

## Success Criteria

- [ ] Permission dialog appears as an always-on-top overlay in Hyprland
- [ ] Keyboard and mouse are captured — no click-through possible
- [ ] Countdown timer auto-denies after 30 seconds
- [ ] App name, resource type, and exact path are clearly displayed
- [ ] "Allow Always" / "Deny Always" persist across `zelxd` restarts
- [ ] `zelx-overlay` crash does not leave any process frozen forever
- [ ] Dialog is not rendered inside the requesting app's window

---

## Known Limitations in This Phase

- Hyprland only (other compositors need `wlr-layer-shell` support)
- Single prompt at a time (queued — later prompts wait)
- No app icon shown (security decision — see design above)
- Network access still not intercepted
- No multi-monitor awareness (appears on primary output)
