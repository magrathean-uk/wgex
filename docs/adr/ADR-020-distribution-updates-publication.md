# ADR-020 Distribution, updates, publication

Status: Accepted 2026-10-25

**Decision.** macOS: Developer ID (G2 certificate in the dedicated keychain), Hardened Runtime, `notarytool`, stapled DMG, Sparkle 2.9.3 (EdDSA; private key supplied to the signing tool from a secret store, never written to the repo or build directory; a documented rotation runbook) with authorised installs onto the root-owned bundle; daemon handoff per `architecture.md` §15; anti-rollback floor. iOS/iPadOS/tvOS: development and ad hoc first, TestFlight internal next, App Store last. **The organisation-enrolment decision is made in phase 0 (P0-17), before App IDs are created**, because App Review 5.4 requires an organisation account for VPN apps and a later account migration has caused 4.3(a) rejections. The public repository is created only after sanitisation (ADR-027). Mac App Store: out of scope.

