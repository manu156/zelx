# RFC-001 — App Identity and cgroup v2

**Status:** Accepted direction; privileged launch protocol and registration design pending.
**Decision:** A privileged registry binds approved launches to kernel cgroup identities.
Cgroup path strings and process names are never proof of application identity.

## Requirements

An identity must survive fork, distinguish users and concurrent instances, and
prevent a caller from borrowing a different app's saved grants. Stable policy
keys must come from approved launch registrations, not from caller-selected
command basenames.

## Alternatives

| Mechanism | Assessment |
|---|---|
| PID/comm | Useful Phase 0–1 metadata; PID reuse and mutable comm names prevent trusted app identity |
| UID per app | Stronger separation, but changes filesystem access and desktop integration; deferred |
| Privileged cgroup registry | Groups descendants without assigning per-app UIDs; selected, subject to launch authorization and protected membership |

## Trust boundary

The privileged launch service owns the Zelx subtree, instance registry, and launch
registrations. The unprivileged frontend submits a launch request over an
authenticated local protocol. The service verifies the registered executable and
launch constraints, starts the child in a protected cgroup, registers the
instance before exec, and runs application code with the caller's credentials.
It must not attach arbitrary caller-supplied PIDs to an existing trusted group.

Kernel cgroup membership is inherited on fork, but migration is controlled by
filesystem permissions and delegation rules. `CAP_SYS_ADMIN` is **not** a
universal prerequisite for migration. Applications must have no writable route
through membership files or delegated ancestors to acquire another identity.
The user systemd manager and `Delegate=yes` scopes are not trusted authorities
against applications with that same UID. See
[cgroup v2 delegation](https://docs.kernel.org/admin-guide/cgroup-v2.html#delegation).

## Registry mapping

```text
kernel cgroup identity -> {owner_uid, registered_policy_id, instance_id}
policy key            -> (owner_uid, registered_policy_id)
audit identity        -> instance_id plus display/executable metadata
```

The path `/zelx.slice/zelx-<instance>.scope` is a diagnostic label. Parsing a
basename, checking a `zelx-` prefix, or stripping a UUID does not authenticate it.
Verify membership against the live registry. Guard process lookups with pidfds
or equivalent lifetime validation, and invalidate caches on exit or
service-controlled moves. `cgroup.events` tracks group emptiness;
`FAN_EVENT_ON_CHILD` does not report process exit.

Unknown groups map to `__unmanaged__`, with no app-specific grants inherited from
the displayed process name. Children of a registered terminal share its policy;
terminal trust selection remains an explicit design decision in RFC-003.

## Limits and acceptance

Cgroup membership does not authenticate the code later loaded by a process.
Registration must define executable updates, user-writable scripts/interpreters,
loader environment, and launch constraints. Same-UID ptrace and process injection
remain limitations until isolation addresses them. Root is trusted and can
reconfigure the system.

[Phase 2](../phases/phase-2-cgroup-identity.md) defines required negative tests for
forged labels, executable substitution, arbitrary PID attachment, delegation,
reuse, and launch ordering. Do not claim unforgeable app identity until that
protocol and its limits have been validated. Current Phase 0–1 comm policy keys
are unchanged by this RFC.
