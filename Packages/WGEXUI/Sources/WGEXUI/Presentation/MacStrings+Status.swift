// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Protection verdicts, lifecycle evidence, stale reports and tunnel health.
public nonisolated extension MacStrings {
    /// Copy used in the session traffic chart and statistic tiles.
    static let stale = "Stale"
    /// Event wording when more than one profile is marked to start before login (M1-02).
    static let moreThanOneProfileStartsBeforeLogin = "more than one tunnel is set to start before login"
    /// Copy used in the event description presenter and the session traffic chart.
    static let trafficBlocked = "Traffic blocked"
    /// Copy used in the Mac details grid and Mac import review.
    static let unavailable = "Unavailable"
    /// Shares the Core inactive label with other platforms.
    static let inactive = UserStrings.inactive
    /// Copy used in the Mac details grid.
    static let unknownServiceStatusIsStale = "Unknown - service status is stale"
    /// Shares the Core unsupported label with other platforms.
    static let unsupported = UserStrings.unsupported
    /// Shares the Core protected label with other platforms.
    static let protected = UserStrings.protected
    /// Copy used in the shared protection presenter and verdict chip labels.
    static let connecting = "Connecting"
    /// Copy used in the shared protection presenter.
    static let checkingTheTunnelAndProtection = "Checking the tunnel and protection"
    /// Copy used in the shared protection presenter and verdict chip labels.
    static let reconnecting = "Reconnecting"
    /// Copy used in the shared protection presenter.
    static let openWGEXToReconnectTraffic = "Open WGEX to reconnect. Traffic stays blocked until then"
    /// Copy used in the shared protection presenter.
    static let theConnectionFailedTheKill = "The connection failed. The kill switch is blocking traffic"
    /// Copy used in the shared protection presenter.
    static let disconnectingTheKillSwitchIs = "Disconnecting. The kill switch is blocking traffic"
    /// Copy used in the shared protection presenter.
    static let theKillSwitchIsBlockingTraffic = "The kill switch is blocking traffic outside the tunnel"
    /// Copy used in the shared protection presenter.
    static let signInToThisNetwork = "Sign in to this network"
    /// Shares the Core unprotected label with other platforms.
    static let unprotected = UserStrings.unprotected
    /// Copy used in the shared protection presenter.
    static let trafficCanLeaveOutsideTheTunnel = "Traffic can leave outside the tunnel"
    /// Copy used in the shared protection presenter.
    static let thisDeviceCannotEnforceAKill = "This device cannot enforce a kill switch"
    /// Copy used in the shared protection presenter.
    static let connected = "Connected"
    /// Copy used in shared profile rows and the shared protection presenter.
    static let notConnected = "Not connected"
    /// Combines the platform limitation with the consequence of a dropped tunnel.
    static func trafficCanLeaveOutsideThe(_ limitation: String) -> String {
        "\(limitation). Traffic can leave outside the tunnel if it drops"
    }

    /// Combines the platform limitation with disconnected traffic behaviour.
    static func trafficLeavesOutsideTheTunnel(_ limitation: String) -> String {
        "\(limitation). Traffic leaves outside the tunnel"
    }

    /// Reason shown before any backend status report has been received.
    static let noReportYet = "No status received yet. Protection cannot be verified."
    /// Copy used in the shared protection presenter.
    static let trafficOutsideTheTunnelIs = ". Traffic outside the tunnel is blocked meanwhile"
    /// Consequence suffix while reconnecting without enforced traffic blocking.
    static let unprotectedMeanwhile = ". Traffic can leave outside the tunnel meanwhile"
    /// Copy used in the shared protection presenter.
    static let networkChangedChecking = "Network changed. Checking protection again"
    /// Copy used in the shared protection presenter.
    static let wokeFromSleepChecking = "Woke from sleep. Checking protection again"
    /// Copy used in the shared protection presenter.
    static let switchingTransportChecking = "Switching transport. Checking protection again"
    /// Copy used in the shared protection presenter.
    static let tryingTheNextEndpointChecking = "Trying the next endpoint. Checking protection again"
    /// Copy used in the shared protection presenter.
    static let theTunnelCouldNotBeVerified = "The tunnel could not be verified. Traffic may leave outside the tunnel"
    /// Names the missing reporter and time since its last report.
    static func hasNotReportedFor(_ reporter: String, _ age: String) -> String {
        "\(reporter) has not reported for \(age)"
    }

    /// Copy used in the shared protection presenter.
    static let vpnExtensionStatusIsUnavailable = "VPN extension status is unavailable"
    /// Copy used in the shared protection presenter.
    static let secureInstallIsNotComplete = "Secure install is not complete. Protection is not enforced until it is"
    /// Copy used in the shared protection presenter.
    static let networkSettingsAreStillBeing = "Network settings are still being applied"
    /// Copy used in the shared protection presenter.
    static let theReportedStateDoesNotMatch = "The reported state does not match this device. Traffic may leave outside the tunnel"
    /// Copy used in the shared protection presenter.
    static let trafficMayLeaveOutsideThe = "Traffic may leave outside the tunnel until WGEX can check again"
    /// Copy used in the status reporter description.
    static let vpnExtension = "VPN extension"
    /// Copy used in verdict chip labels.
    static let noKillSwitch = "No kill switch"
    /// Shares the Core unknown label with other platforms.
    static let unknown = UserStrings.unknown
    /// Neutral status heading before the first backend report.
    static let statusUnknown = "Status unknown"
    /// Copy used in the shared peer-health summary.
    static let connectedTransferring = "Connected, transferring"
    /// Describes an active tunnel with a measured handshake age.
    static func connectedLastHandshake(_ age: String) -> String {
        "Connected, last handshake \(age)"
    }

    /// Copy used in the shared peer-health summary.
    static let connectedIdle = "Connected, idle"
    /// Describes an active tunnel awaiting the peer for a measured duration.
    static func connectedWaitingForThePeer(_ duration: String) -> String {
        "Connected, waiting for the peer (\(duration))"
    }

    /// Describes how long the active peer has not responded.
    static func connectedPeerNotResponding(_ duration: String) -> String {
        "Connected, peer not responding (\(duration))"
    }

    /// Copy used in the shared peer-health summary.
    static let connectedNoNetworkAvailable = "Connected, no network available"
    /// Copy used in the shared peer-health summary.
    static let slowReplies = "Slow replies"
    /// Copy used in the shared peer-health summary.
    static let noResponse = "No response"
    /// Copy used in the shared peer-health summary.
    static let noNetwork = "No network"
    /// Introduces a measured handshake age.
    static func lastHandshake(_ age: String) -> String {
        "last handshake \(age)"
    }

    /// Copy used in the shared peer-health summary.
    static let noHandshakeYet = "no handshake yet"
    /// Fallback name when there is no active profile metadata.
    static let activeTunnel = "the active tunnel"
    /// Copy used in the event description presenter and the Mac details grid.
    static let protectionCannotBeVerified = "Protection cannot be verified"
    /// Qualifier for last-known evidence when the service stops reporting.
    static let lastKnown = "Last known"
    /// Menu row value for the profile that owns the current session.
    static let active = "Active"
}
