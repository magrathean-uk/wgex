// SPDX-License-Identifier: MIT
/// Build compatibility floors are independent of the version of the enclosing app.
public enum ProtocolCompatibility {
    /// Oldest daemon understood by protocol version 8.
    public static let minimumDaemonBuild = 1
    /// Oldest client admitted by protocol version 8.
    public static let minimumClientBuild = 1
}
