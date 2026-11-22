# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 26 October 2026

- First packet through the macOS daemon in the lab guest (macOS 26.6.2, Lab build): app Connect → daemon → kill switch → Linux peer, clean teardown.
- Fixed on the way: pfctl `Token : N` and `-s References` table parsing on macOS 26, rule loads with `-o none`, idle status heartbeat, one shared secret store, imported secret references, clock-based install revisions, wrapping-key provisioning in the lab, secure install grant lifetime.
- Audit and cleanup: dead code removed (placeholder views, `RateSampler`, `WGEXEngineStub`, `ProviderMessageKind`, `LabPendingNetworkAdapters`, unused health helpers, two unused C shims), `BundleLayout` split out of the macOS-only `CodeIdentity` so the Mac backend package builds in the iOS/tvOS matrix again, stray SwiftPM build directories and committed bytecode removed, public docs regenerated from the plan, README status corrected. Findings and the revision 3 plan live in the private plan repository.

### Added

- Repository layout, MIT licence, pinned toolchain (`Toolchain.lock`).
- `just doctor` toolchain check and `just lint` gate with linter self-tests.
- pre-commit configuration and an opt-in pre-push hook running `just check`.
