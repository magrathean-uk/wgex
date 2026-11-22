// SPDX-License-Identifier: MIT

import XCTest

/// UI tests launch the app. The Mac bundle runs only in the VM lab (hard rule:
/// WGEX.app is never launched on the host); iOS and tvOS run in simulators.
public final class WGEXMacUITests: XCTestCase {
    /// A window is on screen after launch (onboarding or the main window).
    @MainActor
    public func testAppPresentsAWindow() {
        let app = XCUIApplication()
        app.launchArguments = ["-WGEXFakeBackend"]
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 10))
    }
}
