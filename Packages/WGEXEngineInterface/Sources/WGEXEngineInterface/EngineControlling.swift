// SPDX-License-Identifier: MIT

import WGEXCore

/// The engine seam (02 §6.4): `EngineActor` over the Go engine and `FakeEngine` in tests conform.
public protocol EngineControlling: Actor {
    /// Creates an engine instance.
    init(configuration: EngineConfiguration) throws(EngineError)
    /// Replaces the whole configuration (`replace_peers=true`). `config` means a previous
    /// full configuration was restored. A first apply has nothing to restore; an
    /// unrecoverable apply or failed restoration closes the device with `deviceClosed`.
    /// Invalid arguments leave the device unchanged.
    func setConfiguration(_ uapi: borrowing UAPIDocument) throws(EngineError)
    /// Updates peer endpoints without session loss.
    func updateEndpoints(_ updates: [PublicKey: Endpoint]) throws(EngineError)
    /// Brings the device up.
    func up() throws(EngineError)
    /// Brings the device down; an already-closed device counts as down.
    func down() throws(EngineError)
    /// Rebinds the UDP sockets to new underlay interfaces.
    func bumpSockets(v4: UInt32?, v6: UInt32?) throws(EngineError)
    /// Swaps the inner transport.
    func setTransport(_ spec: TransportSpec) throws(EngineError)
    /// Expires current keypairs and initiates a handshake with every peer.
    func forceHandshake() throws(EngineError)
    /// A statistics sample.
    func statistics() throws(EngineError) -> TunnelStatistics
    /// Engine log lines.
    var logs: AsyncStream<EngineLogLine> { get }
    /// Engine events, including health and transport events.
    var events: AsyncStream<EngineEvent> { get }
    /// Destroys the instance after draining callbacks; idempotent.
    func shutdown() async
}
