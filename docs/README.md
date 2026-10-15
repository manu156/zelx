# Zelx Documentation

> Zero-trust runtime permissions and real-time syscall auditing for native Linux & Wayland.

## Index

| Document | Purpose |
|---|---|
| [Runtime guide](./runtime.md) | Build, run, configure, and test Phases 0–1 |
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

Each phase has its own acceptance criteria; Phase 0 proves audit plumbing and
does not itself enforce security. The runtime guide distinguishes implemented
behavior, validated tests, prototype limitations, and future design work.
No phase requires a traditional kernel module (`.ko`).

## RFC Index

| RFC | Topic |
|---|---|
| [RFC-001](./rfc/RFC-001-app-identity.md) | App Identity — cgroup v2 vs UID vs PID |
| [RFC-002](./rfc/RFC-002-permission-model.md) | Permission Model — rule grammar, storage, evaluation |
| [RFC-003](./rfc/RFC-003-terminal-heuristic.md) | The Terminal Problem — CLI apps, shells, and session labels |
| [RFC-004](./rfc/RFC-004-kernel-interception-stack.md) | Kernel Interception Stack — fanotify vs seccomp_unotify vs BPF-LSM |
| [RFC-005](./rfc/RFC-005-rust-runtime.md) | Rust runtime, descriptor ownership, and migration boundaries |
