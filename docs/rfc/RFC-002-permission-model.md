# RFC-002 — Permission Model: Rule Grammar, Storage, and Evaluation

**Status:** `Accepted`

---

## Problem

Define how permission rules are expressed, stored, and evaluated. The model must be:
- Expressive enough to cover files, network, devices, IPC
- Simple enough to be understood by non-technical users
- Fast enough to not meaningfully delay syscalls
- Persistent and auditable

---

## Rule Structure

```
(app_id, resource_type, target_pattern, decision, scope)
```

| Field | Type | Examples |
|---|---|---|
| `app_id` | string | `discord`, `firefox`, `__unmanaged__` |
| `resource_type` | enum | `filesystem`, `network`, `microphone`, `camera`, `clipboard`, `screen`, `process_signal` |
| `target_pattern` | glob string | `/home/user/.ssh/**`, `discord.com:443`, `*:*` (any network) |
| `decision` | enum | `ALLOW`, `DENY` |
| `scope` | enum | `ONCE`, `SESSION`, `ALWAYS` |

### Glob semantics for filesystem

| Pattern | Matches |
|---|---|
| `/home/user/.config/discord/` | That exact directory |
| `/home/user/.config/discord/**` | All files recursively inside it |
| `/home/user/.config/discord/*.json` | JSON files directly inside it |
| `/home/user/**` | Everything under home (grant-all) |
| `/home/user/.ssh/**` | All SSH files |

### Glob semantics for network

| Pattern | Matches |
|---|---|
| `discord.com:443` | Exact host and port |
| `*.discord.com:*` | Any Discord subdomain, any port |
| `162.159.135.232:443` | IP + port |
| `*:*` | Any network connection |

---

## Rule Evaluation Order

```
1. Exemption check    — zelxd PID, compositor PID, overlay PID → ALLOW
2. System allowlist   — /usr/**, /lib/**, /etc/fonts/**, etc.  → ALLOW (silent)
3. Rule lookup        — query rules table with most-specific match first
   a. Exact match     — app_id + exact target
   b. Glob match      — app_id + target_pattern GLOB target
   c. Wildcard app    — app_id="*" rules (global policy)
4. No rule found      → PROMPT (send to overlay or CLI)
5. scope=ONCE         → apply decision, do NOT save rule
6. scope=SESSION      → save to in-memory rule cache, clear on zelxd restart
7. scope=ALWAYS       → save to SQLite rules table permanently
```

### Most-specific match wins

If multiple rules match, prefer:
- Longer (more specific) target pattern
- `DENY` over `ALLOW` at equal specificity (secure default)

Example:
```sql
-- App: discord, target: /home/user/.config/discord/settings.json
Rule 1: (discord, filesystem, /home/user/**,                 DENY,  ALWAYS)
Rule 2: (discord, filesystem, /home/user/.config/discord/**, ALLOW, ALWAYS)
-- → Rule 2 wins (more specific path)
```

---

## Storage Schema

```sql
-- Permanent rules
CREATE TABLE rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       TEXT    NOT NULL,
    resource     TEXT    NOT NULL,
    target_glob  TEXT    NOT NULL,
    decision     TEXT    NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    scope        TEXT    NOT NULL CHECK (scope IN ('ONCE', 'SESSION', 'ALWAYS')),
    created_at   INTEGER NOT NULL,  -- Unix ms
    created_by   TEXT    NOT NULL   -- 'user', 'auto', 'import'
);
CREATE INDEX idx_rules_app ON rules (app_id, resource);

-- Append-only audit log
CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    app_id       TEXT    NOT NULL,
    app_instance TEXT    NOT NULL,  -- discord-a3f2b1c8 (with UUID)
    pid          INTEGER NOT NULL,
    resource     TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    decision     TEXT    NOT NULL,  -- ALLOW, DENY, PROMPT_ALLOW, PROMPT_DENY
    rule_id      INTEGER,           -- FK to rules (NULL if ONCE or no rule)
    latency_us   INTEGER            -- microseconds from event to decision
);
CREATE INDEX idx_events_app_ts ON events (app_id, ts);
CREATE INDEX idx_events_ts ON events (ts);
```

---

## In-Memory Cache

`zelxd` maintains an LRU cache of recent rule lookups to avoid SQLite queries
on the hot path:

```c
typedef struct {
    char    app_id[64];
    char    resource[32];
    char    target_hash[32];   // SHA-256 prefix of target string
    int8_t  decision;          // ALLOW=1, DENY=0
    time_t  expires;           // for SESSION scope
} RuleCache;
```

Cache size: 4096 entries. TTL for SESSION rules: zelxd process lifetime.
Cache is invalidated on `zelxctl policy revoke` via an internal signal.

---

## Permission Categories (User-Visible Names)

Technical resource types must map to user-friendly names in the overlay:

| Internal type | Display name | Icon |
|---|---|---|
| `filesystem` | Files & Folders | 📁 |
| `network` | Network Access | 🌐 |
| `microphone` | Microphone | 🎤 |
| `camera` | Camera | 📷 |
| `clipboard` | Clipboard | 📋 |
| `screen` | Screen Capture | 🖥️ |
| `process_signal` | Process Control | ⚠️ |

---

## Default Policy File

A default policy TOML file (`/etc/zelx/default-policy.toml`) ships with Zelx:

```toml
# System-wide auto-allow rules (no prompt required)
[[rules]]
app_id = "*"
resource = "filesystem"
target_glob = "/usr/**"
decision = "ALLOW"
scope = "ALWAYS"

[[rules]]
app_id = "*"
resource = "filesystem"
target_glob = "/lib/**"
decision = "ALLOW"
scope = "ALWAYS"

# ... other system paths

# User can add app-specific rules here or via zelxctl
```
