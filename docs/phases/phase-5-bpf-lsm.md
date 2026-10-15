# Phase 5 — BPF-LSM Policy Enforcement

**Status:** `[ ] Not started — feasibility prototypes required`
**Depends on:** Phase 4
**Goal:** Add kernel policy enforcement and auditing while retaining proven
synchronous permission brokers.

## Scope

`FAN_OPEN_PERM` gates supported file opens, including `openat`/`openat2` paths that
reach the same filesystem hooks. It does not gate every filesystem operation,
network access, process signaling, or IPC. BPF-LSM can cover additional LSM hooks
and apply already established policy inside the kernel.

BPF-LSM is available from Linux 5.7 where enabled, but each required hook, helper,
map, and attachment mode must be probed. A kernel version alone does not establish
that a proposed synchronous prompt mechanism exists. The user-space loader stays
Rust; BPF programs may use the toolchain appropriate to the kernel ABI.

## Permission transport remains explicit

`BPF_F_SLEEPABLE` allows supported helpers/kfuncs that may sleep in allowed hook
contexts. It does **not** itself provide a wait-for-userspace permission primitive.
There is no implemented `zelx_wait_for_decision()` API in Zelx. See
[kernel kfunc documentation](https://kernel.org/doc/html/latest/bpf/kfuncs.html)
and [LSM BPF programs](https://docs.kernel.org/bpf/prog_lsm.html).

Keep fanotify for interactive filesystem decisions and seccomp notification for
the selected network/syscall decisions. Do not replace either solely because a
kernel supports sleepable BPF. Any future replacement needs a runnable prototype
showing request transport, correlation, bounded waits, cancellation, revocation,
and behavior under broker failure before its architecture can be accepted.

For an operation without an applicable synchronous broker, an unknown policy must
deny. It may emit a bounded notification so that a later user-approved retry can
succeed. Never allow an unknown access merely to populate a policy cache: one
successful credential read or connection can be enough for an attack.

## Hook plan

| LSM hook | Intended role | Unknown-policy behavior |
|---|---|---|
| `file_open` | Enforce established file policy, complement fanotify | Continue to the active fanotify gate only when its coverage is guaranteed; otherwise deny |
| `socket_connect` / `socket_create` | Enforce destination/socket policy | Retain the applicable seccomp broker; otherwise deny |
| `task_kill` | Apply registered instance boundaries | Deny cross-instance operations lacking a grant |
| `ptrace_access_check` | Restrict process injection/debugging | Deny unless explicitly authorized |
| `inode_rename` and other selected hooks | Enforce/audit operations fanotify does not gate | Deny protected operations lacking established policy |

These are LSM attachment names, not invented helper APIs. An LSM return of zero
continues kernel processing; it does not itself send an interactive request or
skip a remaining fanotify check. Preserve denial from any preceding LSM program.

## Kernel policy and audit design

- Use the privileged Phase 2 registry to bind cgroup identities to app instances.
  User-controlled cgroup names or application metadata cannot establish trust.
- Define complete policy keys and filesystem identity/namespace semantics before
  implementing the cache. A path hash alone is not a permission key: collisions,
  rename, hard links, and namespace aliases must not transfer grants.
- Publish policy generations and specify revocation ordering across SQLite,
  userspace caches, and BPF maps. A revoke is not acknowledged as complete while
  a backend may still apply an older allow.
- Bound maps, notifications, and outstanding requests. Cache eviction, unknown
  policy, notification loss, and unavailable brokers must never synthesize an
  allow in enforcement mode.
- Correlate BPF and broker events so an early BPF denial is audited and accesses
  passing both mechanisms are not misleadingly counted twice. Ring-buffer
  submission alone neither blocks an access nor guarantees a durable audit row.
- Test hook ordering and failure behavior with other LSM policies enabled.

## Media integration

PipeWire/WirePlumber integration remains a separate authorization broker project.
Select a supported version/API and prototype asynchronous authorization without
blocking its event loop. Authenticate the actual client's registered instance;
do not trust an app-supplied cgroup property. Direct ALSA/V4L2 device access also
needs filesystem/device policy; not all recording goes through PipeWire.

## Transition and validation

1. Prototype the required hook attachments and policy decisions on supported
   kernels, including coexistence with fanotify and seccomp notification.
2. Establish policy identity, generation/revocation, and audit correlation.
3. Add enforcement incrementally; keep the existing brokers active.
4. Benchmark complete cache-hit and prompt paths, queue saturation, and tail
   latency. Prior microsecond figures are targets, not measured guarantees.
5. Consider retiring a broker only after an equivalent mechanism passes its
   coverage, timeout, shutdown, crash, and revocation tests.

## Acceptance criteria

- [ ] Required hooks and helpers are detected; unsupported combinations fail
  clearly or use an explicitly supported broker.
- [ ] No unknown/evicted policy grants access without the applicable broker.
- [ ] Protected operations without a broker deny, including notification loss.
- [ ] Trusted instance mappings and complete cache keys resist impersonation.
- [ ] Revocations invalidate every active backend before completion is reported.
- [ ] Prior LSM denials remain effective and audit correlation is verified.
- [ ] Signaling and ptrace rules separate app instances as specified.
- [ ] Media authorization uses authenticated client identity and tested APIs.
- [ ] Measured performance supports any claims of reduced overhead.

Requirements include BPF-LSM/BTF support, active BPF LSM configuration, and the
specific helpers/attachment modes validated by the prototypes. Pin loader and
media API requirements after those prototypes; a blanket Linux 5.11 or
WirePlumber 0.4 requirement does not prove this design works.
