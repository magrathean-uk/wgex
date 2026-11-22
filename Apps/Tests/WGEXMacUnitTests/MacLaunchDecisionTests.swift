// SPDX-License-Identifier: MIT
import AppKit
import Carbon
import Testing

/// The silent login launch (LOGIN-SILENT, DEC-021) as a pure decision over the launch inputs. The decision sources
/// are compiled in from LaunchSources (symlinks to Apps/WGEXMac) because the hosted bundle cannot import the app module.
@MainActor
private struct MacLaunchDecisionTests {
    private static let loginItem = MacLaunchSignals(isOpenApplication: true, loginItemFlag: true, sender: nil)
    private static let ordinary = MacLaunchSignals(isOpenApplication: true, loginItemFlag: false, sender: "Dock")

    // MARK: Launch inputs

    @Test func `the login-item flag or a login-session sender marks a login launch, nothing else does`() {
        #expect(Self.loginItem.isLoginLaunch)
        #expect(MacLaunchSignals(isOpenApplication: true, loginItemFlag: false, sender: "loginwindow").isLoginLaunch)
        #expect(MacLaunchSignals(isOpenApplication: true, loginItemFlag: false, sender: "BackgroundTaskManagementAgent").isLoginLaunch)
        #expect(!Self.ordinary.isLoginLaunch)
        #expect(!MacLaunchSignals(isOpenApplication: true, loginItemFlag: false, sender: "Finder").isLoginLaunch)
        #expect(!MacLaunchSignals(isOpenApplication: true, loginItemFlag: false, sender: nil).isLoginLaunch)
        // Opening a document or URL is a user request, whatever it carries.
        #expect(!MacLaunchSignals(isOpenApplication: false, loginItemFlag: true, sender: "loginwindow").isLoginLaunch)
    }

    @Test func `the event reduction reads the flag forms and the sender process`() {
        #expect(MacLoginLaunch.signals(nil) == nil)
        let plain = Self.openEvent()
        #expect(MacLoginLaunch.signals(plain) == MacLaunchSignals(isOpenApplication: true, loginItemFlag: false, sender: nil))
        let property = Self.openEvent()
        property.setParam(NSAppleEventDescriptor(enumCode: keyAELaunchedAsLogInItem), forKeyword: keyAEPropData)
        #expect(MacLoginLaunch.signals(property)?.loginItemFlag == true)
        let parameter = Self.openEvent()
        parameter.setParam(NSAppleEventDescriptor(boolean: true), forKeyword: keyAELaunchedAsLogInItem)
        #expect(MacLoginLaunch.signals(parameter)?.loginItemFlag == true)
        let names: (pid_t) -> String? = { $0 == 4242 ? "loginwindow" : nil }
        let sent = MacLoginLaunch.signals(plain, senderPID: { _ in 4242 }, processName: names)
        #expect(sent?.sender == "loginwindow")
        #expect(sent?.isLoginLaunch == true)
        // No sender, or the app itself as sender, names no process.
        #expect(MacLoginLaunch.signals(plain, senderPID: { _ in 0 }, processName: names)?.sender == nil)
        #expect(MacLoginLaunch.signals(plain, senderPID: { _ in getpid() }) { _ in "loginwindow" }?.sender == nil)
        // The real lookup names this process.
        #expect(MacLoginLaunch.processName(getpid()) != nil)
        #expect(!MacLoginLaunch.isLoginLaunch(plain))
    }

    // MARK: Decision

    @Test(arguments: [false, true])
    func `a login-item launch shows no window and no Dock icon`(hideDockIcon: Bool) {
        let decision = MacLaunchPresentation.decide(.launch(Self.loginItem), from: .unlaunched, hideDockIcon: hideDockIcon)
        #expect(decision.presentation.silent)
        #expect(decision.presentation.settled)
        #expect(decision.hidesDock)
        #expect(!decision.opensWindow)
    }

    @Test(arguments: [false, true])
    func `an ordinary launch opens the window and the Dock follows Hide Dock icon`(hideDockIcon: Bool) {
        let decision = MacLaunchPresentation.decide(.launch(Self.ordinary), from: .unlaunched, hideDockIcon: hideDockIcon)
        #expect(!decision.presentation.silent)
        #expect(decision.hidesDock == hideDockIcon)
        #expect(decision.opensWindow)
    }

    @Test(arguments: [false, true])
    func `a reopen after a login launch opens the window and the Dock follows Hide Dock icon`(hideDockIcon: Bool) {
        let login = MacLaunchPresentation(isLoginLaunch: true)
        let hidden = MacLaunchPresentation.decide(.reopen(hasVisibleWindows: false), from: login, hideDockIcon: hideDockIcon)
        #expect(!hidden.presentation.silent)
        #expect(hidden.hidesDock == hideDockIcon)
        #expect(hidden.opensWindow)
        let visible = MacLaunchPresentation.decide(.reopen(hasVisibleWindows: true), from: login, hideDockIcon: hideDockIcon)
        #expect(!visible.presentation.silent)
        #expect(!visible.opensWindow)
    }

    @Test(arguments: [false, true])
    func `a reopen after an ordinary launch keeps the Dock preference`(hideDockIcon: Bool) {
        let decision = MacLaunchPresentation.decide(
            .reopen(hasVisibleWindows: false), from: MacLaunchPresentation(isLoginLaunch: false), hideDockIcon: hideDockIcon,
        )
        #expect(!decision.presentation.silent)
        #expect(decision.hidesDock == hideDockIcon)
        #expect(decision.opensWindow)
    }

    @Test(arguments: [false, true])
    func `a launch without a current event stays silent until an event decides, once`(hideDockIcon: Bool) {
        let waiting = MacLaunchPresentation.decide(.launch(nil), from: .unlaunched, hideDockIcon: hideDockIcon)
        #expect(waiting.presentation == .awaitingEvent)
        #expect(waiting.hidesDock)
        #expect(!waiting.opensWindow)

        let login = MacLaunchPresentation.decide(.launch(Self.loginItem), from: waiting.presentation, hideDockIcon: hideDockIcon)
        #expect(login.presentation == MacLaunchPresentation(isLoginLaunch: true))
        #expect(!login.opensWindow)
        let ordinary = MacLaunchPresentation.decide(.launch(Self.ordinary), from: waiting.presentation, hideDockIcon: hideDockIcon)
        #expect(ordinary.presentation == MacLaunchPresentation(isLoginLaunch: false))
        #expect(ordinary.hidesDock == hideDockIcon)
        #expect(ordinary.opensWindow)

        // A settled launch is never re-decided by a later event.
        let again = MacLaunchPresentation.decide(.launch(Self.ordinary), from: login.presentation, hideDockIcon: hideDockIcon)
        #expect(again.presentation == login.presentation)
        #expect(!again.opensWindow)
    }

    @Test func `the user asking for the window first settles an undecided launch`() {
        var presentation = MacLaunchPresentation.awaitingEvent
        let changed = presentation.windowRequested()
        #expect(changed)
        #expect(presentation == MacLaunchPresentation(isLoginLaunch: false))
        let late = MacLaunchPresentation.decide(.launch(Self.loginItem), from: presentation, hideDockIcon: false)
        #expect(!late.presentation.silent)
        #expect(!late.opensWindow)
    }

    // MARK: Lab launch log

    @Test func `the Lab launch log line carries allowlisted metadata only, never event parameters`() {
        let secretPath = "/Users/someone/Private/secret-tunnel.conf"
        let documents = NSAppleEventDescriptor.appleEvent(
            withEventClass: kCoreEventClass,
            eventID: kAEOpenDocuments,
            targetDescriptor: nil,
            returnID: AEReturnID(kAutoGenerateReturnID),
            transactionID: AETransactionID(kAnyTransactionID),
        )
        let list = NSAppleEventDescriptor.list()
        list.insert(NSAppleEventDescriptor(fileURL: URL(fileURLWithPath: secretPath)), at: 1)
        documents.setParam(list, forKeyword: keyDirectObject)
        documents.setParam(NSAppleEventDescriptor(string: "payload-marker"), forKeyword: keyAEPropData)
        let line = MacLoginLaunch.launchEventSummary(
            stage: "did-finish", event: documents, isDefaultLaunch: false, isLoginLaunch: false,
            senderPID: { _ in 4242 }, processName: { _ in "Finder" },
        )
        #expect(line == "Launch event did-finish: eventClass=aevt eventID=odoc openApplication=false loginItemFlag=false " +
            "senderPID=4242 sender=Finder defaultLaunch=false loginLaunch=false")
        #expect(!line.contains("secret-tunnel"))
        #expect(!line.contains("payload-marker"))

        let login = Self.openEvent()
        login.setParam(NSAppleEventDescriptor(enumCode: keyAELaunchedAsLogInItem), forKeyword: keyAEPropData)
        let loginLine = MacLoginLaunch.launchEventSummary(
            stage: "will-finish", event: login, isDefaultLaunch: nil, isLoginLaunch: true,
            senderPID: { _ in 0 }, processName: { _ in nil },
        )
        #expect(loginLine == "Launch event will-finish: eventClass=aevt eventID=oapp openApplication=true loginItemFlag=true " +
            "senderPID=0 sender=none defaultLaunch=n/a loginLaunch=true")
        let none = MacLoginLaunch.launchEventSummary(stage: "will-finish", event: nil, isDefaultLaunch: nil, isLoginLaunch: false)
        #expect(none == "Launch event will-finish: eventClass=none eventID=none openApplication=false loginItemFlag=false " +
            "senderPID=0 sender=none defaultLaunch=n/a loginLaunch=false")
    }

    private static func openEvent() -> NSAppleEventDescriptor {
        NSAppleEventDescriptor.appleEvent(
            withEventClass: kCoreEventClass,
            eventID: kAEOpenApplication,
            targetDescriptor: nil,
            returnID: AEReturnID(kAutoGenerateReturnID),
            transactionID: AETransactionID(kAnyTransactionID),
        )
    }
}
