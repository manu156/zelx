# Phase 2 — App Identity via cgroup v2

**Status:** `[ ] Not started`
**Depends on:** Phase 1
**Goal:** Associate a verified app launch and its descendants with one policy identity.

## Problem

Phases 0–1 use the process comm name as the policy key. Children can have different
names, and an application can change its name. A cgroup groups a launch and its
descendants, but a cgroup name alone does not authenticate an application.

Membership is inherited at fork. Migration does **not** universally require
`CAP_SYS_ADMIN`: delegated users can move processes when the destination and
common-ancestor permission checks permit it. See the kernel's
[delegation documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#delegation).

## Launch authority

`zelx-run` remains an unprivileged Rust frontend. A privileged launch service owns
the Zelx cgroup subtree and an instance registry. Its responsibilities are:

1. Authenticate the caller using Unix socket peer credentials and authorize the
   requested launch for that UID. Peer credentials alone do not authorize an
   arbitrary app label supplied by another process with the same UID.
2. Resolve the policy ID through a trusted launch registration. Bind it to an
   approved executable, verified through a retained file descriptor, and its
   launch constraints. Do not accept a caller-supplied basename, environment
   variable, cgroup path, or arbitrary PID as proof of identity. User-writable
   executable changes, interpreters, injected code, and loader environment
   variables need explicit registration/approval rules before grants are reused.
3. Allocate an instance ID and create a cgroup controlled by the service. Keep
   membership controls and relevant ancestors unwritable by the application UID.
   Do not delegate the app subtree or allow the caller to attach arbitrary
   processes to an existing instance.
4. Start the child under supervision, place it in the cgroup, and register its
   kernel cgroup identity before releasing it to exec the approved executable.
   Drop to the caller's UID/GID and intended privileges before application code
   runs. Failure at any step aborts the launch.
5. Retain the instance mapping until all descendants exit. Use pidfds for process
   lifecycle and `cgroup.events` for group emptiness; process names are display
   metadata only.

The service-side launch protocol, registration format, executable verification,
and authorization rules must be specified and tested before Phase 2 is accepted.
This phase does not by itself solve same-UID ptrace, writable plugin/configuration
injection, or all other ways to compromise an already trusted process. Those
limits must stay explicit until later isolation work addresses them.

## Identity and policy lookup

The privileged registry maps a kernel cgroup identity to:

| Field | Purpose |
|---|---|
| Owner UID | Keeps different users' policies and instances separate |
| Registered policy ID | Stable key shared by approved launches of an app |
| Instance ID | Unique accounting and audit identity for this launch |
| Display name and verified executable | Information shown in permission requests |

Paths such as `/zelx.slice/zelx-<instance>.scope` are diagnostic labels. Never
derive authority by stripping a prefix/UUID from a path. Resolve a process's
membership against the registry, guard against PID reuse, and reject unknown or
inconsistent mappings. Cache entries must be invalidated on exit and on any
service-controlled membership change. `FAN_EVENT_ON_CHILD` is a file-event flag,
not a process-exit notification mechanism.

Unregistered processes receive the `__unmanaged__` policy identity. An existing
process cannot gain a trusted app identity by requesting a move or changing its
comm name. All children inherit the instance's policy, including CLI tools
launched from a registered terminal.

## systemd integration

On systemd hosts, the privileged launch service should use the **system manager**
to create/manage transient units under a protected Zelx slice, with application
delegation disabled and the application running as its user. Verify actual
ownership and migration permissions, rather than relying on the unit name.

`systemd-run --user --scope --property=Delegate=yes` is not a security identity
backend. The user manager and delegated hierarchy are controlled by the same UID
as the applications. A host without systemd may use a service-owned cgroup v2
subtree with the same launch and registry protocol. Do not manipulate a subtree
behind another cgroup manager's back.

## Terminal trust

[RFC-003](../rfc/RFC-003-terminal-heuristic.md) remains a draft. Terminal policy
must be selected explicitly or through an approved launch registration; a
process name such as `kitty` never grants developer trust automatically. Children
share the selected terminal policy, with that tradeoff made visible to the user.

## Planned CLI

```sh
zelxctl apps                       # registered active instances
zelxctl apps --all                 # include recorded exited instances
zelxctl trace discord --pid 4821   # proposed launch/process filter
```

## Acceptance criteria

- [ ] Approved launches and their children share the registered policy identity.
- [ ] Concurrent launches have distinct instance records and share only the
  intended user's app policy.
- [ ] A process cannot acquire another app's grants through labels, environment,
  forged cgroup names, arbitrary PID attachment, or delegated-cgroup migration.
- [ ] Launch registration rejects an unapproved executable or unsafe change to
  an approved executable/launch configuration.
- [ ] The child cannot run before registration or with the service's privileges.
- [ ] Root-owned and user-delegated cgroups are tested as distinct trust cases.
- [ ] PID/cgroup reuse and launcher failure do not reuse stale instance grants.
- [ ] Stopping an instance through the service stops/reaps its descendants and
  cleans the cgroup only after it is empty. Killing one process need not kill
  all of its children.
- [ ] Unmanaged launches remain gated and cannot impersonate registered apps.

Network interception and the Wayland overlay remain later phases.
