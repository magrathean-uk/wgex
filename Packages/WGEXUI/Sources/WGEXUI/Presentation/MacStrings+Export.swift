// SPDX-License-Identifier: MIT

import Foundation

/// Profile sharing, file/QR export and private-key disclosure warnings.
public nonisolated extension MacStrings {
    /// Copy used in the menu extra and main window.
    static let export = "Export…"
    /// Copy used in the shared profile editor string facade.
    static let exportProfile = "Export Tunnel"
    /// Copy used in the shared profile editor string facade.
    static let shareWithoutKeys = "Share without keys"
    /// Copy used in the shared profile editor string facade.
    static let exportConfigurationFile = "Export configuration file"
    /// Copy used in the shared profile editor string facade.
    static let exportPrivateKey = "Export private key?"
    /// Copy used in the shared profile editor string facade.
    static let thisFileContainsThePrivateKey = "This file contains the private key and any preshared keys. Anyone with the file can use this tunnel. Save it only to a location you trust."
    /// Copy used in the shared profile editor string facade.
    static let exportFileWithKeys = "Export file with keys"
    /// Copy used in the shared profile editor string facade.
    static let showQRCode = "Show QR code"
    /// Copy used in the shared profile editor string facade.
    static let thisQRCodeContainsThePrivate = "This QR code contains the private key. Anyone who scans it can use this tunnel."
    /// Copy used in the shared profile editor string facade.
    static let thisConfigurationIsTooLargeFor = "This configuration is too large for a QR code. Export a file instead."
    /// Copy used in the menu extra and main window.
    static let exportAllTunnels = "Export All Tunnels…"
    /// Title of the confirmation before every tunnel's keys are written to one archive.
    static let exportAllTitle = "Export all tunnels?"
    /// Warning shown before the archive of every tunnel is written.
    static let exportAllWarning = "This .zip contains the private key and any preshared keys of every tunnel. Anyone with the file can use all of them. Save it only to a location you trust."
    /// Confirm button of the all-tunnels export.
    static let exportAllWithKeys = "Export All with Keys"
    /// Default file name offered for the all-tunnels archive.
    static let exportAllFilename = "wgex-tunnels.zip"
    /// Shown when more tunnels exist than one archive can hold for re-import.
    static let exportAllTooMany = "There are more tunnels than one .zip can hold (1,024). Export fewer tunnels and try again."
    /// Shown when the tunnels together exceed the archive size limit.
    static let exportAllTooLarge = "The tunnels are too large for one .zip. Export fewer tunnels and try again."
    /// Menu bar command that opens the same importer as the main window.
    static let importTunnelsCommand = "Import Tunnels…"
    /// Copy used in the shared profile editor string facade.
    static let theConfigurationCouldNotBe = "The configuration could not be exported. Check that its keys are available and try again."
}
