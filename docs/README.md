# Zelx Documentation

> Zero-trust runtime permissions and real-time syscall auditing for native Linux & Wayland.

## Index

| Document | Purpose |
|---|---|
| [Architecture](./architecture.md) | Full system design — components, layers, data flows |
| [Threat Model](./threat-model.md) | What we protect against, attacker model, explicit non-goals |
| [Phases](./phases/) | Progressive implementation roadmap (Phase 0 → 6) |
| [RFCs](./rfc/) | Key design decisions and their rationale |

## Phases at a Glance

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6
fanotify    +runtime     +cgroup     +Wayland    +network    +BPF-LSM    +namespaces
 logging     prompts     identity     overlay    (seccomp)   deep hooks  full isolat.
```

Each phase is independently usable and ships real security value.
No phase requires a traditional kernel module (`.ko`).

## RFC Index

| RFC | Topic |
|---|---|
| [RFC-001](./rfc/RFC-001-app-identity.md) | App Identity — cgroup v2 vs UID vs PID |
| [RFC-002](./rfc/RFC-002-permission-model.md) | Permission Model — rule grammar, storage, evaluation |
| [RFC-003](./rfc/RFC-003-terminal-heuristic.md) | The Terminal Problem — CLI apps, shells, and session labels |
| [RFC-004](./rfc/RFC-004-kernel-interception-stack.md) | Kernel Interception Stack — fanotify vs seccomp_unotify vs BPF-LSM |
