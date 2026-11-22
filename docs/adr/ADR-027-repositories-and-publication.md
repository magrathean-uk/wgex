# ADR-027 Repositories and publication

Status: Accepted 2026-10-25

**Context.** Planning and research notes can mention personal locations, infrastructure, secret-manager item names, keychain paths and API-key profile names. gitleaks catches keys, not prose.

**Decision.** The public repository holds code, `docs/` with sanitised ADRs, architecture, threat model and user documentation, and no planning or research material. `Tools/lint/check-public-prose.sh` with a denylist (personal location, server names, secret-manager item names, local paths, key profile names) runs in `just check`, and a sign-off precedes the first push of the public repository.
