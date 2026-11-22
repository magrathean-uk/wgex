# ADR-025 Privileged helper placement and the admin-to-root boundary

Status: Accepted 2026-10-25

**Decision (corrected).** A user-owned bundle in `/Applications` can be rewritten by any process running as that user, and a replaced daemon cannot detect itself; bundle self-validation is therefore an integrity check for accidents, not a security boundary. **Secure install is v1 (P4-22):** after approval the daemon makes `WGEX.app` root-owned and non-group/world-writable, refuses privileged operations while any bundle file is writable by a non-root user, and Sparkle uses authorised installs. The daemon plist carries launch constraints (`SpawnConstraint`, `ResponsibleProcessConstraint` with team, signing identifier and validation category) if the VM shows launchd enforces them for `SMAppService` daemons (P4-22 records the result). Release daemons refuse to run outside `/Applications`; the app shows "Move to Applications". The remaining interim exposure (between first launch and secure install) is documented.

