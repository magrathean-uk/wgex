// SPDX-License-Identifier: MIT
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface

package extension TunnelController {
    /// Confirms the daemon's own utun immediately after its configure and before any route or resolver depends on it
    /// (M1-18). The identity no longer contains the kernel's ifi_lastchange, which XNU moves on its own, so nothing is
    /// adopted: the device confirms name, index, this process's descriptor, the assigned addresses and the engine that
    /// holds the descriptor; the journal must still record this identity for the generation. Anything else fails closed
    /// while the blocking policy stays loaded.
    func confirmOwnTunnel(_ identity: TunnelIdentity, engine: any EngineControlling?, generation: Generation) async throws {
        // Off the actor, like the configure before it; the generation is re-checked before the identity is judged.
        let current = try await offActor(.confirm) { try await OffActor.confirm(ports.device, identity: identity, engine: engine) }
        try check(generation)
        guard current == identity, resource(generation).identity == identity else {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.ownership(.tunnelIdentityDrift)
            #endif
            throw DaemonFailure.portNotOwned
        }
    }
}
