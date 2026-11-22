# Test key fixtures

**These are test fixtures. They are not real keys.** They were generated once
with Go's `crypto/ecdh` X25519 using the same clamping as `wg genkey`, are
committed on purpose, and protect nothing. Never use them on a real peer, a
real server or a real device profile; never copy a real key into this
directory (plan rule 13: no key that is active on another device in any test).

| File | Contents |
|---|---|
| `server.key`, `server.pub` | private and public key of the test server (test peer) |
| `client1.key`, `client1.pub` | first test client |
| `client2.key`, `client2.pub` | second test client |
| `psk1.key` | preshared key |

Format: every file starts with the line `# WGEX TEST FIXTURE - NOT A REAL KEY`,
followed by exactly one line holding the 44-character standard-base64 key
(32 bytes, trailing newline). **Readers must skip lines starting with `#`**;
`testpeer --key-file` and any fixture loader must do so. The private keys are
clamped as `wg genkey` clamps them, and each `.pub` is the X25519 public key of
the matching `.key`.

Rules:

- Test code reads keys only from this directory (or generates throwaway keys).
- The secret scanner (`Tools/lint/check-no-secrets-in-strings.sh`) allows
  key-shaped strings only under `Tests/Fixtures/`, `Vendor/` and
  `Engine/go/vendor/`; the same values anywhere else in Swift, Go or YAML
  sources fail the lint (proved by `Tools/lint/run-selftests.sh`).
- `gitleaks` reports the committed `.conf` vectors (the `PrivateKey` lines); the
  repository-root `.gitleaks.toml` allows the path `Tests/Fixtures/` only, and
  the same strings anywhere else are still reported.
- To rotate, delete the files and regenerate all of them together; the conf
  vectors in `../conf/` embed these keys and must be regenerated with them.
