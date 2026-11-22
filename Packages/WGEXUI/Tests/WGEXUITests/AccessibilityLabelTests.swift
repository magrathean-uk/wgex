// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

/// Every component's VoiceOver label is non-empty in every state.
private struct AccessibilityLabelTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test(arguments: PresentationCases.all)
    func `orb and chip labels name the state`(_ testCase: PresentationCase) {
        let presentation = testCase.presentation
        let transport = OrbChip(slot: .transport, glyph: "arrow.left.arrow.right", title: "Relay", colour: .transport)
        let orb = ConnectionOrb.accessibilityLabel(for: presentation, transport: transport)
        #expect(orb.hasPrefix("Tunnel status: \(presentation.primary)."))
        #expect(orb.hasSuffix("Transport: Relay."))
        #expect(!ConnectionOrb.accessibilityLabel(for: presentation).isEmpty)
        #expect(StateChip.accessibilityLabel(title: presentation.verdict.chipTitle) == "Protection: \(presentation.verdict.chipTitle)")
        if let chip = presentation.healthChip {
            #expect(orb.contains(chip.accessibilityLabel))
        }
    }

    @Test
    func `stat tiles and sparklines`() {
        let values: [StatValue] = [
            .rate(1500),
            .bytes(42),
            .age(since: now.addingTimeInterval(-18), now: now),
            .text("utun7"),
            .unavailable,
        ]
        for value in values {
            for stale in [false, true] {
                let label = StatTile.accessibilityLabel(title: "Download", value: value, isStale: stale)
                #expect(label.hasPrefix("Download, ") && label.count > "Download, ".count)
                #expect(label.hasSuffix(", stale") == stale)
            }
        }
        #expect(!Sparkline.accessibilityLabel(title: "Upload", series: SparklineSeries(), now: now).isEmpty)
    }

    @Test
    func `events timeline rows`() throws {
        let kinds: [TunnelEvent.Kind] = [
            .phaseChanged, .handshakeCompleted, .txWithoutRx, .endpointChanged, .transportChanged(nil), .transportChanged(TransportID()),
            .pathChanged, .failed(.anotherTunnelActive), .failed(.profileNotFound(UUID())), .failed(.invalidConfiguration(.invalidProfile)),
            .failed(.secretsUnavailable), .failed(.backendUnavailable), .failed(.permissionDenied), .failed(.timedOut),
            .failed(.engine(code: -5)), .failed(.cancelled),
        ] + [ProtectionState.protected, .blocked, .captiveWindow(expires: now), .unprotected, .unsupported, .unknown]
            .map { .protectionChanged($0) }
        let utc = try #require(TimeZone(identifier: "UTC"))
        let locale = Locale(identifier: "en_GB")
        for kind in kinds {
            let event = TunnelEvent(date: now, kind: kind, generation: nil)
            let label = EventsTimeline.accessibilityLabel(for: event, timeZone: utc, locale: locale)
            let time = EventsTimeline.timeText(now, timeZone: utc, locale: locale)
            #expect(time.contains("8:00"), "\(time)")
            #expect(label == "\(time), \(EventDescription.describe(kind).text)")
            #expect(!EventDescription.describe(kind).text.isEmpty)
        }
    }

    @Test(arguments: ServiceState.allCases, [false, true])
    func `service state card rows`(_ state: ServiceState, _ running: Bool) {
        let progress = ServiceSetupProgress(state: state, daemonRunning: running)
        #expect(progress.steps.map(\.id) == ["registered", "approval", "enabled", "running"])
        for step in progress.steps {
            #expect(ServiceStateCard.accessibilityLabel(for: step).hasPrefix("\(step.title): \(step.state.spoken)"))
        }
        #expect(progress.needsApproval == (state == .requiresApproval))
        #expect(progress.steps[3].state == (state == .enabled && running ? .done : (state == .enabled ? .current : .pending)))
    }

    @Test
    func `unregistered service and missing plist have distinct copy and attention states`() {
        let unregistered = ServiceSetupProgress(state: .notRegistered, daemonRunning: false)
        #expect(unregistered.steps[0].state == .current)
        #expect(unregistered.steps[0].detail == "Register the background service to continue")
        let missing = ServiceSetupProgress(state: .notFound, daemonRunning: false)
        #expect(missing.steps[0].state == .attention)
        #expect(missing.steps[0].detail == "The background service's launchd plist is missing from this copy of WGEX. Reinstall WGEX")
    }

    @Test
    func `secure install, warning sheet, banner and onboarding`() {
        for state in SecureInstallState.all {
            #expect(SecureInstallCard.accessibilityLabel(for: state).hasPrefix(state.title))
            #expect(!state.detail.isEmpty)
            #expect((state.actionTitle == nil) == (state == .checking || state == .verified))
        }
        #expect(WarningSheet.accessibilityLabel(for: .forceAllTraffic) == "Warning: Force all traffic")
        for remaining in [300.0, 272, 1, 0, -10] {
            #expect(CaptiveWindowBanner.accessibilityLabel(remaining: remaining).hasPrefix("Sign-in window. "))
        }
        #expect(OnboardingCopy.stepLabel(index: 2, count: 7) == "Step 2 of 7")
    }

    @Test
    func `fields`() {
        for phase in SecretRevealState.Phase.allCases {
            let label = SecretField.accessibilityLabel(title: "Private key", phase: phase)
            #expect(label.hasPrefix("Private key, "))
        }
        for validation in [FieldValidation.empty, .valid, .invalid("Invalid address")] {
            #expect(CIDRField.accessibilityLabel(title: "Address", validation: validation).hasPrefix("Address, "))
        }
        for model in [AllowedIPsModel(), AllowedIPsModel(["0.0.0.0/0", "::/0"]), AllowedIPsModel(["bad"])] {
            #expect(AllowedIPsEditor.accessibilityLabel(for: model).hasPrefix("Allowed IPs, "))
        }
    }

    @Test(arguments: [nil] + ProtectionVerdict.allCases.map(Optional.some))
    func `profile rows and cards`(_ verdict: ProtectionVerdict?) throws {
        let endpoints: [(Endpoint?, Int)] = try [
            (#require(try? Endpoint(validatingHost: "vpn.example.com", port: 51820)), 1),
            (#require(try? Endpoint(validatingHost: "2001:db8::1", port: 1)), 3),
            (nil, 1),
            (nil, 2),
        ]
        for (endpoint, peers) in endpoints {
            let summary = ProfileSummary(id: UUID(), name: "Home", endpoint: endpoint, peerCount: peers, verdict: verdict)
            #expect(summary.accessibilityLabel.hasPrefix("Home, \(summary.stateTitle), "))
            #expect(!summary.endpointSummary.isEmpty)
            if verdict == .stale || verdict == .unknown || verdict == nil {
                #expect(!summary.stateColour.isProtectionColour)
            }
        }
    }
}
