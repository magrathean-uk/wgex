// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Events the engine reports (02 §4.1, §6.4, §8.2). Health is driven by these,
/// not by UI sampling.
public enum EngineEvent: Sendable, Hashable {
    /// Carrier transport events (phase 6).
    public enum Transport: Sendable, Hashable {
        /// The carrier connected.
        case carrierConnected
        /// The carrier disconnected.
        case carrierDisconnected(reason: String)
        /// The relay rejected the credentials.
        case authFailed
        /// The relay certificate did not verify.
        case certificateMismatch
    }

    /// Device lifecycle notifications; consumers must handle fatal closure.
    case engine(EngineLifecycleEvent)

    /// A handshake with `peer` completed.
    case handshakeCompleted(peer: PublicKey, at: Date)
    /// Data or a handshake initiation was sent and nothing came back since `since`.
    case txWithoutRx(since: Date)
    /// Data was received.
    case rx(at: Date)
    /// The engine observed a new endpoint for `peer`.
    case endpointChanged(peer: PublicKey, endpoint: Endpoint)
    /// A transport event.
    case transport(Transport)
}

/// Lifecycle notifications contain only fixed reasons and outcomes.
public enum EngineLifecycleEvent: Sendable, Hashable {
    /// A closed engine cannot be restarted; destroy it before creating a replacement.
    case deviceClosed(EngineDeviceClosedReason)
    /// A rejected configuration was rolled back; the previous device configuration remains active.
    case configRestored
    /// The asynchronous socket rebind finished successfully or exhausted its retry budget.
    case socketsBumped(ok: Bool)
}

/// Stable C ABI reason codes for a fatal device closure.
public enum EngineDeviceClosedReason: Int32, Sendable, Hashable {
    /// Upstream closed the device after a tun read error or an unsolicited close.
    case tunReadError = 1
    /// No previous configuration could be restored after a rejected configuration.
    case configurationRejected = 2
    /// A future engine supplied a reason this client does not recognise.
    case unknown = 0
}
