# Phase 0 and Phase 1 runtime

The Rust implementation provides passive filesystem auditing (`--audit-only`) and
runtime permission enforcement (the default). It is an early prototype with
PID/comm identity; it is not the Phase 6 isolation boundary.

## Build

Requirements: Linux 4.20+ (filesystem marks), `CONFIG_FANOTIFY=y`,
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`, a supported filesystem, Rust 1.85+ and Cargo,
pkg-config, and system SQLite development files. Make is an optional wrapper.
The simulated integration suite also uses a C compiler for two independent
test-only ABI fixtures; no project C code is linked into production binaries.
Python 3 is needed for tests. The running daemon needs `CAP_SYS_ADMIN` in the
initial user namespace; ordinary user-namespace root is insufficient.

```sh
cargo build --locked
make
make test
make test-runtime
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

Cargo produces `target/debug/zelxd`, `target/debug/zelxctl`, and
`target/debug/zelx-run`; `make` copies them to `build/` for the examples and
integration tests. Use `cargo build --locked --release` for optimized binaries,
or `make PROFILE=release` to put those binaries in `build/`.
`make install` supports `PREFIX` (default `/usr/local`) and `DESTDIR`.
The shipped `config/default-policy.toml` documents the baseline; Phase 1 uses
compiled defaults and does not load TOML at runtime.

## Run

Start with audit mode in one terminal:

```sh
sudo ./build/zelxd --audit-only --watch "$HOME"
```

In another terminal, launch a command and inspect its events:

```sh
./build/zelx-run cat "$HOME/.profile"
sudo ./build/zelxctl trace cat --last 1h
sudo ./build/zelxctl trace --all --last 5m
```

Stop the daemon with Ctrl-C. To enable prompts, run it in the foreground:

```sh
sudo ./build/zelxd --watch "$HOME" --tty "$(tty)"
```

The five choices are allow once, allow always, deny once, deny always, and allow
session. Grants from prompts cover **exactly the displayed path**, including
literal `*`, `?`, `[` and `]` characters. Use policy commands to grant a directory
pattern. `ONCE` is never stored; `SESSION` exists only in daemon memory; `ALWAYS`
is stored in SQLite. Sessions expire on daemon restart.

Without `--tty`, terminal stdin and stderr are used. If either is not a terminal,
unknown accesses are denied immediately. EOF, invalid input, and timeout deny.
Denied opens return `EPERM` (errno 1) with the current `FAN_CLASS_CONTENT` /
`FAN_DENY` implementation, as specified in
[fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html).
The test opener exits with that errno; both simulated and real tests require it.
`--timeout 30` is the default; values from 1 to 300 seconds are accepted. Every
request's deadline starts at receipt, including time spent queued behind another
prompt. No input from a previous prompt is accepted for the next prompt.

`--max-pending 64` bounds the worker queue and retained permission requests;
values 1–1024 are accepted. The effective limit is reduced to fit the process's
open-file limit, reserving 64 descriptors for runtime operations and event reads.
Startup fails if that reserve leaves no request capacity. Event reads adopt at
most 32 descriptors per batch. The ready message reports the effective limit.

When capacity is exhausted, enforcement denies excess opens immediately while
the reader continues handling events and exemptions. Audit-only mode continues
allowing opens. Excess requests are counted in bounded `OVERLOAD` audit summaries
with app `__zelx__`; the JSON target records `denied`, `allowed`, `first_ts`, and
`last_ts`. These summaries explicitly replace per-path detail during overload.
They are queued when capacity returns and drained during graceful shutdown.
Crash/audit failure can still lose an unwritten summary. Increasing queue limits
does not eliminate the kernel's own queue limits or the documented crash behavior.

`--watch DIR` may be repeated (64 roots maximum); the default is `/home`.
Interception applies to **all processes** accessing those roots, including apps
launched outside `zelx-run`. The launcher currently preserves arguments and exit
status and sets an informational environment hint. It does not create a sandbox
or a trustworthy identity.

Pass `--exempt-pid PID` for the compositor, future overlay, or another trusted
component. Exemptions are explicit; process names never grant exemptions.
PID file descriptors stop a dead PID's exemption from being reused
(`--exempt-pid` needs Linux 5.3+ for `pidfd_open`). The daemon,
its threads, and PID 1 are exempt. A shared user-session cgroup is never exempted;
only a dedicated `zelxd.service` or `zelxd.scope` in a root-controlled cgroup can
receive the daemon-cgroup exemption.

## Policies and audit storage

```sh
sudo ./build/zelxctl policy list
sudo ./build/zelxctl policy list cat
sudo ./build/zelxctl policy add cat allow "/home/user/Documents/**" always
sudo ./build/zelxctl policy add cat deny "/home/user/Documents/private/**" always
sudo ./build/zelxctl policy revoke cat filesystem
sudo ./build/zelxctl policy export > zelx-policy.json
sudo ./build/zelxctl policy import zelx-policy.json
```

`policy add` creates filesystem rules with scope `always`. `policy list` and
`export` show permanent rules; session grants are private to the running daemon.
Import accepts a version-1 JSON object with a `rules` array of permanent rules,
validates the whole file, then appends rules in one transaction. It assigns new
IDs and records the import time and creator. It does not erase existing rules.
Imports are limited to 8 MiB. Revoke removes matching permanent **and session**
rules; rule changes are visible on the next evaluation without restarting.
Session grants record the latest committed revocation ID at creation: a revoke
that preceded the grant cannot erase it, including a revoke issued while its
prompt was displayed. A later matching revoke invalidates the grant.
Other resource categories can be stored/imported for future phases but are not
intercepted yet.

Evaluation follows RFC-002: exemptions, baseline system paths, app-specific
rules (exact before glob), then global `app_id="*"` rules. Longer patterns win;
equal-specificity ties prefer deny. `*` matches within one path component, `**`
crosses slashes, and `?`, bracket expressions, and backslash quoting are supported.
POSIX named classes use ASCII semantics; unknown classes and reversed ranges
match nothing, including when negated.
The pattern `/dir/` is equivalent to `/dir`; trailing separators on absolute
patterns are normalized before matching and specificity comparison. Use `/dir/**`
for descendants and `/dir` separately for the directory itself. These text
policies do not encode a separate file-type constraint.

The default database is `/var/lib/zelx/zelx.db`, created with private permissions.
Use `--db FILE` on both programs for another location; `ZELX_DB` is also accepted
by the CLI. The root daemon requires a root-owned database directory with trusted
parents and a private, owned, regular database file. Keep the database and its
WAL/lock files in that directory. CLI access to the default database requires
sudo. Running the daemon as the same UID as an untrusted app cannot provide audit
tamper resistance.

Audit records include Unix millisecond timestamps, comm name, PID, an
`app_instance` label (`comm:pid`), resource,
target, decision (`ALLOW`, `DENY`, `PROMPT_ALLOW`, `PROMPT_DENY`, or an `OVERLOAD`
summary), optional rule ID,
and monotonic decision latency in microseconds. Executable and cgroup details
are collected with the request for future identity work; Phase 1 stores comm and
PID in the schema from RFC-002. Trace is ordered by timestamp then event ID and
escapes terminal control bytes in app names and paths. Rule IDs in old events
remain historical identifiers after revocation.
Literal backslashes display as `\\` and nonprinting/non-ASCII bytes as `\xNN`,
so a filename containing a control byte cannot resemble a literal escape string.

## Implementation and limits

The fanotify reader exclusively owns the permission descriptors (`OwnedFd`) and
responds to its own opens without waiting for database or
prompt work. A worker evaluates policy, prompts, persists permanent decisions,
and appends audit records **after** the reader acknowledges the kernel response.
Typed channels connect the reader and worker; mutable request objects and file
descriptors are not shared. See [RFC-005](./rfc/RFC-005-rust-runtime.md). A reader-side
watchdog independently denies expired active and queued requests. A 4096-entry
LRU caches evaluations; database revision triggers invalidate cached decisions
on policy changes, and revocation records invalidate session grants. Audit writes
do not invalidate the policy cache.
Work is sent with nonblocking bounded channel operations; the reader never waits
for queue space. The pending and expired-request maps share the same request
budget, so expiration cannot move requests into an unbounded secondary queue.
The worker has at most one active item in addition to its bounded queue.

Before enabling filesystem marks, the daemon installs persistent inode ignore
marks for its database, WAL, and shared-memory files. These three storage files
are excluded from permission interception and auditing even under a watched root;
ordinary filesystem ownership and permissions protect them. Merely responding to
their events as exempt is insufficient: closing a fanotify event descriptor for
one of these files can release SQLite's process-wide POSIX locks, leaving the
worker attached to deleted WAL files and stale policy state. See
[SQLite's lock warning](https://www.sqlite.org/howtocorrupt.html#posix_advisory_locks_canceled_by_a_separate_thread_doing_close).
Startup fails if any storage exclusion cannot be installed. The live SQLite
connection keeps the sidecars present until interception stops. Do not rename,
replace, or unlink live database files. Database creation also avoids opening
and closing an existing database outside SQLite.

Filesystem marks are broad; resolved paths are filtered against component
boundaries of configured roots before policy or auditing. Nested filesystems
present at startup are marked separately. Unsupported marks fail startup. New
mounts added later require a daemon restart. Bind aliases, hard links outside a
watched root, inaccessible/changed mount namespaces, and deleted/renamed paths
are not a hard isolation boundary. Unresolvable event paths deny in enforcement
mode and are recorded as `<unresolved>`.

`FAN_OPEN_PERM` gates file opens, not read/write operations on already-open file
descriptors, and cannot undo earlier accesses or `O_TRUNC` side effects. It does
not cover every filesystem operation (for example unlink and rename), networks,
media, IPC, or namespace escapes. The allowlist applies to an open as a whole;
it does not establish read-only mount permissions. Process comm names can be
changed/spoofed and are limited by the kernel; children get their own identities.
These limitations are the reasons for the later cgroup and isolation phases.

SIGINT/SIGTERM denies received pending requests in enforcement mode, closes the
fanotify group before joining the worker, then drains queued audit records.
Unanswered kernel requests are **allowed** when the last fanotify group descriptor
closes, including after SIGKILL. Thus crashes are fail-open and may lose queued
audit entries. Queue overflow, response failures, and audit-write failures are
reported; the daemon shuts down when coverage or auditing is lost. There is no
automatic supervisor/restart policy yet.

Kernel API references: [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html)
and [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html).

## Validation

```sh
make test           # Rust unit tests and CLI/launcher integration tests
make test-runtime   # daemon regressions using a simulated fanotify transport
make test-kernel    # builds as your user, then uses sudo for real kernel tests
```

Run `make test-kernel` without wrapping Make in sudo. Cargo uses your normal
user's Rust toolchain; only the Python kernel suite needs root. Running
`sudo make test-kernel` would select root's Rust configuration, so the target
rejects that invocation before building. No root Rust toolchain is required.
The equivalent explicit steps are:

```sh
make all build/zelx-open
sudo env ZELX_SIMULATED=0 python3 tests/test_kernel.py
```

The simulated transport is a test-only preload library; production binaries have
no simulation mode. It exercises metadata handling, responses, procfs identity,
real terminal prompts, SQLite, rule updates, timeout queues, explicit PID
exemptions, graceful shutdown, and crash cleanup. Its event descriptors use
ordinary read-only opens to reproduce SQLite lock interactions, and it models
inode ignore marks. It does **not** verify kernel
hook coverage, real EPERM delivery, mount behavior, or generation of the daemon's
own SQLite-open events. The real-kernel suite uses a permission fanotify group
and adds a nested tmpfs mount test. Its database-under-watch case checks for
self-open deadlocks. The suite fails clearly if privileges are unavailable and
watches only disposable temporary directories, never the user's home.

Rust migration validation (2026-10-15): debug and optimized builds, 11 Rust unit
tests, 9 Python CLI compatibility tests, and 11 simulated daemon regressions
passed (the twelfth daemon test, nested mounts, requires real kernel privileges).
Formatting and strict Clippy checks passed. Regression coverage includes the
frozen C schema, preserved historical IDs, atomic import rollback, launcher
argument bytes/signals, non-UTF-8 paths, late input, and audit-write failures.
C sanitizer/static-analysis results are not evidence for this Rust rewrite.
A user-run kernel suite reached all 12 tests and exposed incorrect `EACCES`
expectations in the eight denial scenarios: the kernel correctly returned
`EPERM`. The assertions and simulated opener now require `EPERM`. A subsequent
kernel run passed 11 tests, including nested mounts, but exposed SQLite lock loss
from fanotify event descriptors: external revocation could leave a stale allow
in a detached WAL. Persistent storage-inode ignore marks fix this interaction.
The expanded regression checks ten grant/revoke cycles, warm cache invalidation,
stable storage inodes, and all 31 audit records. Disabling the ignore marks in a
temporary fixture reproduces the user's stale allow and deleted WAL/SHM files;
the fixed simulated suite passes. The subsequent user-run `make test-kernel`
passed all 12 tests in 2.623 seconds, including nested mounts and the expanded
external-revocation regression. A separate SQLite connection test also checks external
revocation against a warmed policy cache. The nested-mount test is skipped only
in simulation; the real-kernel suite requires privileges and fails without them.

Protected non-UTF-8 event paths are denied in enforcement mode and audited with
escaped bytes. Audit mode still allows them. They are never converted lossily
into a different policy target; the current text schema cannot grant them.

Trace also escapes raw filename bytes already present in old C audit records.
Existing non-UTF-8 policy patterns are rejected rather than decoded lossily.

Post-review validation (2026-10-15): 14 Rust unit tests, 10 CLI tests, and 15
simulated daemon tests pass; formatting and strict Clippy checks pass. New
regressions cover queue saturation and graceful shutdown, audit-mode overload
accounting, grants after revoke during a prompt, directory rules, and ambiguous
filename display. The expanded real-kernel suite has 16 tests and requires a
new privileged run; the earlier 12-test result describes the baseline commit.
