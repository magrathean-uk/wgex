# ADR-013 NetworkExtension provider design

Status: Accepted 2026-10-25

**Decision.** As revision 1 with these corrections: the utun descriptor scan runs in Go (`wgex_find_utun_fd`) because the kernel-control headers are absent from the iOS/tvOS SDKs, with the packet-descriptor bridge (`tun_kind = 1`) as the fallback; `includeAllNetworks`, the exclusions and `enforceRoutes` are set on `NEVPNProtocol` by the app-side `ProtocolConfigurationBuilder` (they are unavailable on `NEPacketTunnelNetworkSettings` in the 27 SDK); `tunnelRemoteAddress` is the constant `127.0.0.1`; endpoint resolution uses Network-framework parameters that require the physical interface; `sleep()` never calls `down`; wake forces a handshake per ADR-005; `allowFailover = false`; stop reasons are mapped by their SDK names (corrected 25 October 2026: raw value 17 is `NEProviderStopReasonInternalError`, not a system restart; there is no dedicated restart reason); stats are produced inside the provider; process-wide memory settings via `wgex_configure_process`.

