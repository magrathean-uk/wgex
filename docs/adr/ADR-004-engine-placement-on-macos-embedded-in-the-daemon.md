# ADR-004 Engine placement on macOS: embedded in the daemon

Status: Accepted 2026-10-25

**Decision.** The daemon links `libwgex.a`; one process owns engine, routes, DNS, pf and journal. Process-wide Go settings (memory limit, GC percent) are configured once per process (`wgex_configure_process`). Privilege separation of the engine is a backlog item.

