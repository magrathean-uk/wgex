# ADR-003 macOS backend: root launch daemon with pf, not NetworkExtension

Status: Accepted 2026-10-25

**Decision.** Unsandboxed SwiftUI app plus an `SMAppService` root launch daemon that embeds the Go engine, creates the utun, programs addresses, routes and DNS natively, owns a pf anchor for the kill switch, keeps a crash-safe journal, and exposes typed, mutually authenticated XPC (ADR-012). No installer, no sudo; the user approves the daemon once in System Settings. Apple's TN3165 and WWDC25 session 234 discourage pf and route-table manipulation; Mullvad, IVPN, PIA and Windscribe ship it via Developer ID. WGEX accepts this with: a compatibility matrix on every macOS 27.x point release (AirDrop, Continuity, Sidecar, Mac Virtual Display, Internet Sharing, Xcode device debugging, Screen Time filters, other VPNs), conditional restoration of only WGEX-owned state, a runtime pf evaluation self-test and liveness monitor (ADR-010), and a designed NE system-extension fallback (`WGEXNEProvider` already exists for iOS/tvOS). If a macOS release breaks pf or route ownership and no fix exists within one release cycle, this ADR is superseded and the sysext backend is built.

**Rejected.** NE system extension as primary; hybrid daemon plus sysext; SMJobBless; GUI as root.

