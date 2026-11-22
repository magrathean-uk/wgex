# ADR-008 Keys and secret storage

Status: Accepted 2026-10-25

**Decision.**
- Generation and derivation via CryptoKit. `SecretBytes` is `~Copyable`, `mmap`+`mlock` backed, wiped on deinit, never `Codable`, never `String`; secrets cross XPC as a separate binary `Data` argument with a fixed layout, never inside the Codable envelope and never through JSON. Zeroisation is best effort: Foundation, XPC and Go-heap copies are transient and not wiped; the daemon disables core dumps.
- Apps store secrets in the data-protection Keychain, access group `$(AppIdentifierPrefix)<base>`, `AfterFirstUnlockThisDeviceOnly`, no sync. On macOS this requires `keychain-access-groups` and therefore a provisioning profile embedded in the Mac app (Development and Developer ID profiles, ADR-016).
- The Mac daemon keeps secrets in its root store (`/Library/Application Support/WGEX/secrets/`, 0700/0600, wrapped with a key held in the System keychain or derived from the Secure Enclave, decided by spike P1-18; Time Machine exclusion applied and tested) **while a profile is intended-up or has start-before-login**, so a crashed daemon can recover without the app; they are deleted on explicit disconnect or profile removal. UI copy states that FileVault protects the store only while the Mac is off and that a boot connection starts after the first unlock.
- Each device has its own peer; import warns `keyInUseElsewhere`. The Mac status view no longer offers Send to Apple TV (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift:111`).
- Pasteboard copies of keys are local-only and expire after 60 s.

