// SPDX-License-Identifier: MIT

import XCTest

/// Build here; execute only when a tvOS runtime or approved Apple TV is available.
public final class WGEXTVUITests: XCTestCase {
    @MainActor
    public func testFirstRunAndEmptyState() {
        let app = XCUIApplication()
        app.launchArguments = ["-WGEXFakeBackend"]
        app.launch()
        XCTAssertTrue(app.otherElements["tv.firstRun"].waitForExistence(timeout: 10))
        let proceed = app.buttons["Continue"]
        for _ in 0 ..< 8 where !proceed.hasFocus {
            XCUIRemote.shared.press(.down)
        }
        XCTAssertTrue(proceed.hasFocus)
        XCUIRemote.shared.press(.select)
        XCTAssertTrue(app.buttons["Add from iPhone or Mac"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Paste a configuration"].exists)
    }
}
