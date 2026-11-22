// SPDX-License-Identifier: MIT

import XCTest

public final nonisolated class WGEXiOSUITests: XCTestCase {
    @MainActor
    public func testOnboardingPasteAddAndActivate() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-WGEXFakeBackend"]
        app.launch()
        defer { app.terminate() }
        XCTAssertTrue(app.staticTexts["Your connection. Your server."].waitForExistence(timeout: 15))
        for _ in 0 ..< 5 {
            app.buttons["Continue"].tap()
        }
        app.buttons["Finish setup"].tap()
        showList(in: app)
        let add = app.buttons["wgex.addProfile"]
        XCTAssertTrue(add.waitForExistence(timeout: 5))
        add.tap()
        let paste = app.buttons["wgex.importPaste"]
        XCTAssertTrue(paste.waitForExistence(timeout: 5))
        paste.tap()
        let field = app.textViews["wgex.pasteConfiguration"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        try field.typeText(fixture())
        if app.buttons["wgex.pasteDone"].exists {
            app.buttons["wgex.pasteDone"].tap()
        }
        let review = app.buttons["wgex.reviewConfiguration"]
        if !review.isHittable {
            app.swipeUp()
        }
        review.tap()
        let confirm = app.buttons["Add"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 5))
        XCTAssertTrue(confirm.isEnabled)
        confirm.tap()
        showList(in: app)
        let row = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'wgex.tunnel.row.'")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.tap()
        let toggle = app.switches["wgex.tunnel.switch"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        toggle.tap()
        XCTAssertEqual(
            XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '1'"), object: toggle)], timeout: 5),
            .completed,
        )
        XCTAssertTrue(app.staticTexts["Active"].waitForExistence(timeout: 5))
        attach(app, name: "tunnel-active")
    }

    @MainActor
    public func testFirstScreenListsTunnelsPagesAndAddTunnel() {
        for appearance in ["light", "dark"] {
            let app = XCUIApplication()
            app.launchArguments = ["-WGEXFakeBackend", "-WGEXFakeScenario", "protected", "-WGEXAppearance", appearance]
            app.launch()
            showList(in: app)
            XCTAssertTrue(app.buttons["wgex.addProfile"].waitForExistence(timeout: 15))
            for page in ["General", "Protection", "Log", "About"] {
                XCTAssertTrue(app.staticTexts[page].exists, page)
            }
            XCTAssertFalse(app.tabBars.firstMatch.exists)
            attach(app, name: "first-screen-\(appearance)")
            app.terminate()
        }
    }

    @MainActor
    public func testDebugHarnessConnection() {
        let app = XCUIApplication()
        app.launchArguments = ["-WGEXFakeBackend", "-WGEXFakeScenario", "unprotected"]
        app.launch()
        defer { app.terminate() }
        showList(in: app)
        XCTAssertTrue(app.staticTexts["General"].waitForExistence(timeout: 15))
        app.staticTexts["General"].tap()
        app.buttons["Debug"].tap()
        app.buttons["Load fixture"].tap()
        let store = app.buttons["Store reviewed fixture"]
        if !store.isHittable {
            app.swipeUp()
        }
        XCTAssertTrue(store.isEnabled)
        store.tap()
        let connect = app.buttons["Connect / disconnect"]
        if !connect.isHittable {
            app.swipeUp()
        }
        connect.tap()
        let status = app.staticTexts["wgex.debugStatus"]
        XCTAssertEqual(
            XCTWaiter
                .wait(
                    for: [XCTNSPredicateExpectation(predicate: NSPredicate(format: "label BEGINSWITH 'Protected.'"), object: status)],
                    timeout: 5,
                ),
            .completed,
        )
        connect.tap()
        XCTAssertEqual(
            XCTWaiter.wait(for: [XCTNSPredicateExpectation(
                predicate: NSPredicate(format: "label BEGINSWITH 'Unprotected.'"),
                object: status,
            )], timeout: 5),
            .completed,
        )
        attach(app, name: "debug-harness-disconnected")
    }

    /// iPhone starts on the list; on iPad the list is the sidebar, shown if it is collapsed.
    @MainActor
    private func showList(in app: XCUIApplication) {
        if app.buttons["wgex.addProfile"].waitForExistence(timeout: 2) {
            return
        }
        let back = app.navigationBars.buttons.element(boundBy: 0)
        if app.buttons["Show Sidebar"].exists {
            app.buttons["Show Sidebar"].tap()
        } else if back.exists {
            back.tap()
        }
    }

    private func fixture() throws -> String {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 4 {
            root.deleteLastPathComponent()
        }
        return try String(contentsOf: root.appendingPathComponent("Tests/Fixtures/conf/single-peer-full-tunnel.conf"), encoding: .utf8)
    }

    @MainActor
    private func attach(_ app: XCUIApplication, name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
