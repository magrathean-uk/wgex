// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// App/window commands, common actions, quit consequences and operation messages.
public nonisolated extension MacStrings {
    /// Copy used in Mac setup and Settings navigation.
    /// Copy used in the Mac events list and toast.
    static let dismiss = "Dismiss"
    /// Shares the Core cancel label with other platforms.
    static let cancel = UserStrings.cancel
    /// Copy used in the menu extra and main window and Mac application scenes and menu commands.
    static let quitWGEX = "Quit WGEX"
    /// Copy used in Mac application scenes and menu commands and the shared profile editor string facade.
    static let done = "Done"
    /// Copy used in Mac application scenes and menu commands.
    static let aboutWGEX = "About WGEX"
    /// Application command that revisits the setup flow.
    static let setupCommand = "Set Up WGEX…"
    /// Application name in window titles and About.
    static let appName = "WGEX"
    /// Menu containing the global connection command.
    static let tunnelMenu = "Tunnel"
}
