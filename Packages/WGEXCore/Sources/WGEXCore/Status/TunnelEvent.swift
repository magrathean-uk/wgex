// SPDX-License-Identifier: MIT

import Foundation

/// One entry of the bounded recent-events list in ``TunnelStatus``. Events
/// carry only enum reasons, numeric codes and typed identifiers; no free-form text is retained.
public struct TunnelEvent: Codable, Sendable, Hashable {
    /// What happened.
    public enum Kind: Codable, Sendable, Hashable {
        /// The lifecycle phase changed.
        case phaseChanged
        /// A handshake completed.
        case handshakeCompleted
        /// Data was sent without a reply for a health window.
        case txWithoutRx
        /// The engine observed a new peer endpoint.
        case endpointChanged
        /// The active transport changed.
        case transportChanged(TransportID?)
        /// The underlying network path changed.
        case pathChanged
        /// Protection changed.
        case protectionChanged(ProtectionState)
        /// The tunnel failed.
        case failed(TunnelError)
    }

    /// When it happened.
    public var date: Date
    /// What happened.
    public var kind: Kind
    /// Generation it belongs to, if any.
    public var generation: Generation?

    /// Creates an event.
    public init(date: Date, kind: Kind, generation: Generation?) {
        self.date = date
        self.kind = kind
        self.generation = generation
    }
}
