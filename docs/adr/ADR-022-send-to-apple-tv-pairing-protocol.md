# ADR-022 Send to Apple TV: pairing protocol

Status: Accepted 2026-10-25

**Decision.** QR mode authenticates the TV's key through the QR; manual mode uses commit-then-reveal of the TV's ephemeral key and a **6-digit SAS derived with the HPKE exporter over the full transcript, confirmed on both devices before the sender seals anything**. Suite `HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly` with `info = "wgex-pair v1" ‖ sid ‖ pk_TV ‖ pk_S`. No session id in the Bonjour TXT record; attempts counted after the SAS stage; no system URL scheme; ≤ 64 KiB payload; 120 s single-use sessions; nothing persisted before acceptance. A MITM harness (substituted key, SAS grinding) is an acceptance test. The typed 6-digit code of revision 1 is removed (it added nothing cryptographically). Fallback when pairing is impossible: **paste import on the TV** through the Continuity Keyboard (P5-31), and the sender explains LAN blockers before pairing.

The Mac app no longer offers Send to Apple TV (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift:111`).
