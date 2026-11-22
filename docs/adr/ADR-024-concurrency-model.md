# ADR-024 Concurrency model

Status: Accepted 2026-10-25

As revision 1 (actors, `nonisolated` defaults outside UI, `@convention(c)` trampolines with `Unmanaged` boxes, `Mutex`, `withTaskCancellationShield`), with the TSan gate split by spike P1-03a: Go concurrency under `go test -race` through a cgo harness; Swift concurrency under TSan against `FakeEngine`; dynamic isolation checks against the real engine without TSan, unless the spike shows TSan and the c-archive coexist.

