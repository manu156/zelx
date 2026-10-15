# RFC-005 — Rust runtime and ownership boundaries

**Status:** Accepted
**Decision:** Implement Zelx's user-space runtime in Rust, using Cargo.

## Rationale

The daemon runs with filesystem-interception privileges and handles untrusted
process names, paths, kernel records, and concurrent permission deadlines. Rust
provides checked ownership and memory-safe collections for this code. It does not
make policy, kernel behavior, or deadlock assumptions correct automatically.

Replace the Phase 0–1 C daemon, CLI, and launcher with Rust binaries backed by a
shared library. Keep the CLI commands, SQLite schema version 1, JSON policy
format version 1, matching precedence, session lifetime, and timeout behavior.
Existing rules and audit logs must remain readable without export/import.
The shell launcher becomes a Rust `exec` wrapper, retaining the informational
`ZELX_APP_ID` hint, argument bytes, PID, and command exit behavior.

## Ownership and concurrency

- The event reader exclusively owns the fanotify group, every pending event
  `OwnedFd`, and the deadline watchdog. Neither group nor permission descriptors are cloned into a worker.
- A single worker exclusively owns the SQLite connection, policy LRU, session
  grants, and terminal handles. Safe channels carry requests and decisions.
- Before enabling filesystem monitoring, install inode ignore marks that survive
  modification for the database and its live WAL/SHM files. Closing a fanotify
  event descriptor for these inodes would release the worker's process-wide
  SQLite POSIX locks. A PID exemption applied after reading events cannot
  prevent this. These storage files rely on ordinary filesystem permissions;
  they are excluded from interception and audit. Never open/close an existing
  database outside SQLite while a connection may hold locks on it.
- A nonblocking wakeup pipe makes completed decisions immediately pollable.
  The reader acknowledges the actual kernel response before the worker persists
  a grant or appends its audit record. Expired requests cannot save late grants.
- A shared atomic cancellation flag is the only shared mutable runtime state.
  SIGINT/SIGTERM cancel prompts; the reader denies received pending requests,
  closes the group, and services outstanding acknowledgements while the worker
  drains audit records. A worker error or panic triggers shutdown as well.
- Keep synchronous threads: a general async executor adds no value to this
  bounded set of blocking kernel, SQLite, and terminal operations.

## Unsafe boundary

Linux syscall/TTY wrappers live in `src/linux.rs`. Each unsafe block must explain
pointer validity, buffer length, or descriptor ownership. Parse fanotify metadata
from checked byte slices without casting buffers to aligned structs. Use
`OwnedFd`, `File`, and `BorrowedFd` to make descriptor lifetime visible in types.
Policy, database, identity, CLI, and daemon orchestration use safe Rust and deny
unsafe code. Kernel names and numeric ABI constants remain Linux-specific.

`rusqlite` wraps system SQLite; `serde`/`serde_json` provide typed policy backups;
`clap` parses command lines; `signal-hook` installs cancellation handlers; `lru`
bounds cached policy decisions. Commit Cargo.lock and use locked builds.

Filesystem paths stay `PathBuf`/`OsString` through filtering. This schema uses
UTF-8 text for policy targets: a protected non-UTF-8 event path is denied in
enforcement mode, recorded with escaped bytes, and never matched or granted
using lossy decoding. Audit-only mode still allows it. Terminal output escapes
control and non-ASCII bytes. Non-UTF-8 policy targets require a future schema and
backup-format decision, rather than silently granting the wrong path.

## Validation and scope

Use Rust unit tests for matching, scopes, cache invalidation/eviction, metadata
validation, prompt failure paths, storage checks, and byte preservation. Reuse
Python CLI and daemon integration tests to check the public behavior independently
of implementation language. The small C opener and fanotify preload fixture are
test-only ABI tools; no production binary links project C code. `make` remains a
convenience wrapper around Cargo and the Python/fixture tests.

Required checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, CLI tests, and simulated daemon tests. Real fanotify tests still
require initial-namespace `CAP_SYS_ADMIN`; a simulation does not prove kernel
coverage. Document unavailable privileged validation explicitly.

The migration does not implement cgroup app identity, Wayland, networking,
BPF-LSM, or namespace isolation. Later user-space components should use Rust;
small compositor ABI adapters, illustrative kernel C snippets, and BPF programs
may remain C/C++ where appropriate.
