# WGEX

WGEX is an open-source WireGuard client for Apple platforms. It pairs a native
SwiftUI interface with a userspace WireGuard engine built from the upstream Go
implementation. On macOS it runs the tunnel from a privileged helper daemon; on
iOS and tvOS it uses a Network Extension packet tunnel provider.

**Status: pre-alpha.**
- macOS: there is no public notarised release. As a dated milestone (26 October
  2026) the app, privileged daemon and kill switch connected end to end inside the
  project's macOS 26 lab VM with ad hoc signing.
- iOS: a real Network Extension packet tunnel path exists and runs on devices.
- tvOS: the Network Extension is not wired yet; the app runs against fakes only.

See `CHANGELOG.md`.

## Platforms

- macOS 26
- iOS 27 / iPadOS 27
- tvOS 27

## Building

Tooling has minimum versions in [`Toolchain.lock`](Toolchain.lock); newer is fine. Run `just doctor` to
compare the local toolchain against the lock file and `just --list` for the
available recipes. See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## Licence

MIT; see [`LICENSE`](LICENSE). Security reports: see [`SECURITY.md`](SECURITY.md).

Questions and proposals: use GitHub Issues for public discussion.
