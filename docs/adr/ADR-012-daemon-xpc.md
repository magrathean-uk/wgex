# ADR-012 Daemon XPC

Status: Accepted 2026-10-25

**Decision.** `NSXPCConnection` with `.privileged`; a client-exported `WGEXClientEventsXPC` interface for daemon-to-client events and the `provideSecrets` callback (NSXPC replies are one-shot); secrets as a separate `Data` argument; binary property-list envelopes; `listener.setConnectionCodeSigningRequirement` plus per-connection `setCodeSigningRequirement` on the daemon, the daemon requirement on the client before `resume()`; requirement strings generated from `BuildIdentifiers` with Debug (`.dev`) and Release variants that also use different Mach service names; Release strings require the Developer ID intermediate and leaf OIDs and exclude `get-task-allow`; daemon-allocated generations; the authorisation table in `architecture.md` §5 (owner uid, console user, admin right `manage-protection`, no cross-uid access); anti-rollback floor. The macOS 26 Swift XPC overlay was evaluated and rejected because it exposes no peer uid or audit session. The `installCLISymlink` request and the `manage-any` right from revision 1 are removed.

