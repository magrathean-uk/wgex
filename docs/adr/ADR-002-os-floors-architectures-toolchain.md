# ADR-002 OS floors, architectures, toolchain

Status: Accepted 2026-10-25

**Decision.** Deployment targets macOS 26.0 (amended 25 October 2026, below; originally 27.0), iOS/iPadOS 27.0, tvOS 27.0; `arm64` only. Toolchain pinned to Xcode 27.2 (27B52) in `Toolchain.lock` (amended 31 October 2026, below; originally Xcode 27.1 (27A9275)); Swift 6.4 in Swift 6 language mode; `swift-tools-version: 6.4`; explicit upcoming-feature flags (`NonisolatedNonsendingByDefault`, `InferIsolatedConformances`, `MemberImportVisibility`, `ExistentialAny`); `SWIFT_DEFAULT_ACTOR_ISOLATION=MainActor` on UI targets and packages only; strict memory safety on the engine bridge and packet-path modules; warnings are errors in `just check`. Go 1.27.3 pinned by `toolchain go1.27.3` with `GOTOOLCHAIN=local`.

Device matrix: an **iPad is the default `.device` test target**; `just test-device` refuses a daily-use phone's UDID unless `WGEX_OWNER_DEVICE_OK=1` is set. Oldest supported hardware classes (iPhone 11/SE 2, iPad Pro A12Z, Apple TV 4K 2nd generation, entry Apple silicon Mac) are tested when available, and hardware that is not available is not claimed as tested. Foldable iPhone size classes are part of the UI matrix.

---

**Amendment (25 October 2026).** The macOS floor drops to **macOS 26.0**: the VM lab uses a macOS 26 (Tahoe) guest instead of downloading a 25 GB macOS 27 restore image, and Tahoe users are in scope at launch. iOS and tvOS floors stay at 27. Consequences: `project.yml` and every `Package.swift` declare `.macOS(.v26)`; the engine's macOS slice is built with `-macos=26.0` against the 27 SDK and `verify-slices.sh` expects minos 26.0 for it; code that needs a 27-only API carries an `@available(macOS 27, *)` branch with a 26 fallback (list kept in `docs/architecture.md`). Residual risk: hosts that run macOS 27 get 27-specific pf and DNS findings verified only on 26 until a 27 guest exists; the cutover runbook (P4-25) must include a 27 re-run of the pf and DNS matrix rows before any daily machine moves.

**Amendment (31 October 2026).** The toolchain pin moves to **Xcode 27.2 (27B52), Swift 6.4.2 (swiftlang-6.4.2.1.9)**: the development toolchain moved to Xcode 27.2. The language level stays Swift 6.4 in Swift 6 mode with `swift-tools-version: 6.4`; deployment floors and the installed iOS 27.0 simulator runtime are unchanged. `just check` and the simulator steps of `just check-full` passed on 27.2 without compiler errors; the simulator package build logged one clang `-Wincompatible-sysroot` warning, with no 27.1 log to compare against (M1-22).

