# WGEXEngine

`EngineActor` owns a Go engine handle, serialises ABI calls and drains the
callback dispatcher before releasing its callback box. UAPI documents are
borrowed from their wiped mapping; statistics use WGEXCore's guarded decoder.
`EngineLinkage.provenance` reads the build information embedded in the archive.

Build the five production slices with `just engine`. Products always use the
real engine; tests use `FakeEngine` from `WGEXTesting` (the former `WGEXEngineStub` was removed on 26 October 2026).

The macOS integration archive contains a complete Go runtime. It replaces the
production archive in a test build; linking both would duplicate archive and
header outputs. Build it with `just engine-test`, then run:

```sh
just test WGEXEngine  # real engine, dynamic actor isolation checks, 500 cycles
just test-tsan       # real engine, TSan, 100 cycles plus concurrent owners
just test engine     # Go netstack HTTP/session integration

source Config/Scripts/lib.sh
WGEX_ENGINE_TEST_SUPPORT=1 swift test --package-path Packages/WGEXEngine \
  --scratch-path "$(build_root)/spm/engine-integration" \
  -c release -Xswiftc -enable-actor-data-race-checks
```

`WGEX_ENGINE_TEST_SUPPORT=1` selects the test-only binary target and Clang
module. Keep it unset for product builds and the package dependency linter.
A plain `swift test` exercises the production provenance (no stub; `FakeEngine` covers callers);
`just check` also invokes the real-engine integration suite explicitly.

The log and event streams keep their newest 1024 elements. If a consumer falls
behind, `callbackDrops` reports cumulative log/event drops in a separate stream
that keeps its latest sample. The fixed `EngineEvent` contract has no diagnostic
or internal engine-notification cases; internal Go notifications are ignored.
Callbacks copy their borrowed payloads synchronously and never wait for consumers.

Tests use gVisor netstack tuns and packet socketpairs. They create no host tunnel
or network configuration. The test archive needs Security for Go's HTTP/X.509
support; production mobile slices need CoreFoundation for Go bundle discovery.
