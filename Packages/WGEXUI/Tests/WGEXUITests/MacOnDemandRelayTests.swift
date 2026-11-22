// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXUI

    @MainActor
    private final class FakeLocation: MacLocationAuthorising {
        var status: MacLocationStatus
        var promptAnswer: MacLocationStatus
        private(set) var prompts = 0
        private var observers: [AsyncStream<MacLocationStatus>.Continuation] = []

        init(status: MacLocationStatus = .authorised, promptAnswer: MacLocationStatus = .authorised) {
            self.status = status; self.promptAnswer = promptAnswer
        }

        func requestIfNeeded() async -> MacLocationStatus {
            guard status == .notDetermined else { return status }
            prompts += 1
            status = promptAnswer
            change(to: promptAnswer)
            return promptAnswer
        }

        func changes() -> AsyncStream<MacLocationStatus> {
            let (stream, continuation) = AsyncStream<MacLocationStatus>.makeStream()
            observers.append(continuation)
            return stream
        }

        /// What `locationManagerDidChangeAuthorization` does: the status moves, every observer hears it.
        func change(to new: MacLocationStatus) {
            status = new
            for observer in observers {
                observer.yield(new)
            }
        }
    }

    @MainActor
    private final class FakeWiFi: MacWiFiReading {
        var defaultInterfaceName: String? = "en0"
        var reading: MacWiFiRead = .ssid("Home")
        private var observers: [AsyncStream<String>.Continuation] = []

        func read(interfaceName _: String) -> MacWiFiRead {
            reading
        }

        func changes() -> AsyncStream<String> {
            let (stream, continuation) = AsyncStream<String>.makeStream()
            observers.append(continuation)
            return stream
        }

        func announceChange(_ interfaceName: String) {
            for observer in observers {
                observer.yield(interfaceName)
            }
        }
    }

    @MainActor
    private final class Reports {
        var sent: [WiFiObservation] = []
        var failing = false
    }

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacOnDemandRelayTests {
        private struct Rig {
            let relay: MacOnDemandRelay
            let location: FakeLocation
            let wifi: FakeWiFi
            let reports: Reports
            let requests: AsyncStream<String>.Continuation
            let subscriptions: AsyncStream<Void>.Continuation
            let task: Task<Void, Never>

            func stop() {
                task.cancel()
                requests.finish(); subscriptions.finish()
            }
        }

        private func makeRig(
            location: FakeLocation = FakeLocation(), armedWithList: Bool = true, clock: TimeInterval = 123.5,
        ) async -> Rig {
            let wifi = FakeWiFi()
            let reports = Reports()
            let (requests, requestInput) = AsyncStream<String>.makeStream()
            let (subscriptions, subscriptionInput) = AsyncStream<Void>.makeStream()
            let relay = MacOnDemandRelay(
                requests: { requests }, subscriptions: { subscriptions }, location: location, wifi: wifi,
                clock: { clock },
                report: { observation in
                    reports.sent.append(observation)
                    if reports.failing {
                        throw DaemonError.notAuthorised(.notAppClient)
                    }
                },
            )
            relay.armedWithSSIDList = { armedWithList }
            let task = Task { await relay.run() }
            // Let `run()` install its stream consumers before the test feeds events.
            for _ in 0 ..< 50 {
                await Task.yield()
            }
            return Rig(
                relay: relay, location: location, wifi: wifi, reports: reports, requests: requestInput,
                subscriptions: subscriptionInput, task: task,
            )
        }

        private func settled(_ rig: Rig, count: Int) async {
            for _ in 0 ..< 2000 where rig.reports.sent.count < count {
                await Task.yield()
            }
        }

        private func quiet(_ rig: Rig) async {
            for _ in 0 ..< 200 {
                await Task.yield()
            }
        }

        // MARK: wifiNetworkRequested

        @Test(arguments: [true, false])
        func `every wifiNetworkRequested sends a report whatever the armed state`(_ armedWithList: Bool) async {
            let rig = await makeRig(armedWithList: armedWithList)
            rig.requests.yield("en0")
            await settled(rig, count: 1)
            #expect(rig.reports.sent == [WiFiObservation(interfaceName: "en0", reading: .ssid("Home"), observedAtContinuous: 123.5)])
            rig.requests.yield("en1")
            await settled(rig, count: 2)
            #expect(rig.reports.sent.last?.interfaceName == "en1")
            rig.stop()
        }

        @Test
        func `without Location the report is notAuthorised even though CoreWLAN could answer`() async {
            let rig = await makeRig(location: FakeLocation(status: .denied))
            rig.requests.yield("en0")
            await settled(rig, count: 1)
            #expect(rig.reports.sent.first?.reading == .notAuthorised)
            rig.stop()
        }

        @Test
        func `an undecided Location is also notAuthorised and never prompts from a request`() async {
            let location = FakeLocation(status: .notDetermined)
            let rig = await makeRig(location: location)
            rig.requests.yield("en0")
            await settled(rig, count: 1)
            #expect(rig.reports.sent.first?.reading == .notAuthorised)
            #expect(location.prompts == 0)
            rig.stop()
        }

        @Test(arguments: [
            (MacWiFiRead.notAssociated, WiFiReading.notAssociated), (.unreadable, .unreadable),
            (.ssid(""), .unreadable), (.ssid(String(repeating: "a", count: 33)), .unreadable),
            (.ssid(String(repeating: "a", count: 32)), .ssid(String(repeating: "a", count: 32))),
        ])
        func `readings map to the wire and an impossible name becomes unreadable`(_ read: MacWiFiRead, _ wire: WiFiReading) async {
            let rig = await makeRig()
            rig.wifi.reading = read
            rig.requests.yield("en0")
            await settled(rig, count: 1)
            #expect(rig.reports.sent.first?.reading == wire)
            #expect(rig.reports.sent.first?.isWellFormed == true)
            rig.stop()
        }

        @Test
        func `a daemon refusal is dropped and the next request still reports`() async {
            let rig = await makeRig()
            rig.reports.failing = true
            rig.requests.yield("en0")
            await settled(rig, count: 1)
            rig.reports.failing = false
            rig.requests.yield("en0")
            await settled(rig, count: 2)
            #expect(rig.reports.sent.count == 2)
            rig.stop()
        }

        @Test
        func `a request naming an impossible interface is not relayed`() async {
            let rig = await makeRig()
            rig.requests.yield("not a valid interface name")
            await quiet(rig)
            #expect(rig.reports.sent.isEmpty)
            rig.stop()
        }

        // MARK: Armed with a list

        @Test
        func `each Location authorisation change reports while armed with a list`() async {
            let rig = await makeRig()
            rig.location.change(to: .denied)
            await settled(rig, count: 1)
            #expect(rig.reports.sent.last?.reading == .notAuthorised)
            rig.location.change(to: .authorised)
            await settled(rig, count: 2)
            #expect(rig.reports.sent.last?.reading == .ssid("Home"))
            rig.location.change(to: .denied)
            await settled(rig, count: 3)
            #expect(rig.reports.sent.last?.reading == .notAuthorised)
            rig.stop()
        }

        @Test
        func `a Location change reports for the requested interface when CoreWLAN's default differs`() async {
            let rig = await makeRig()
            rig.requests.yield("en1")
            await settled(rig, count: 1)
            #expect(rig.reports.sent.last?.interfaceName == "en1")
            rig.location.change(to: .denied)
            await settled(rig, count: 2)
            #expect(rig.reports.sent.last == WiFiObservation(interfaceName: "en1", reading: .notAuthorised, observedAtContinuous: 123.5))
            rig.location.change(to: .authorised)
            await settled(rig, count: 3)
            #expect(rig.reports.sent.last == WiFiObservation(interfaceName: "en1", reading: .ssid("Home"), observedAtContinuous: 123.5))
            #expect(rig.reports.sent.map(\.interfaceName) == ["en1", "en1", "en1"])
            rig.stop()
        }

        @Test
        func `a Location change follows the latest request and ignores an impossible one`() async {
            let rig = await makeRig()
            rig.requests.yield("en1")
            rig.requests.yield("en2")
            await settled(rig, count: 2)
            rig.requests.yield("not a valid interface name")
            await quiet(rig)
            rig.location.change(to: .denied)
            await settled(rig, count: 3)
            #expect(rig.reports.sent.map(\.interfaceName) == ["en1", "en2", "en2"])
            rig.stop()
        }

        @Test
        func `a Location change before any request reports for the default interface`() async {
            let rig = await makeRig()
            rig.location.change(to: .denied)
            await settled(rig, count: 1)
            #expect(rig.reports.sent.map(\.interfaceName) == ["en0"])
            rig.stop()
        }

        @Test
        func `CoreWLAN SSID and link changes and the subscription start report while armed with a list`() async {
            let rig = await makeRig()
            rig.wifi.reading = .ssid("Cafe")
            rig.wifi.announceChange("en1")
            await settled(rig, count: 1)
            #expect(rig.reports.sent.last == WiFiObservation(interfaceName: "en1", reading: .ssid("Cafe"), observedAtContinuous: 123.5))
            rig.subscriptions.yield()
            await settled(rig, count: 2)
            #expect(rig.reports.sent.last?.interfaceName == "en0")
            rig.stop()
        }

        @Test
        func `nothing is reported unprompted when no armed profile lists networks`() async {
            let rig = await makeRig(armedWithList: false)
            rig.location.change(to: .denied)
            rig.wifi.announceChange("en0")
            rig.subscriptions.yield()
            await quiet(rig)
            #expect(rig.reports.sent.isEmpty)
            rig.stop()
        }

        @Test
        func `a Mac without Wi-Fi hardware reports nothing unprompted`() async {
            let rig = await makeRig()
            rig.wifi.defaultInterfaceName = nil
            rig.subscriptions.yield()
            rig.location.change(to: .denied)
            await quiet(rig)
            #expect(rig.reports.sent.isEmpty)
            rig.stop()
        }
    }

    private extension MacOnDemandRelayTests {
        // MARK: Asking for Location

        @Test(arguments: [
            (OnDemandPolicy.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), 1),
            (.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), 1),
            (.always(exceptSSIDs: ["Home"]), 1),
            (.interfaces(.wifiOrEthernet(.anySSID)), 0),
            (.interfaces(.ethernetOnly), 0),
            (.off, 0),
        ])
        func `Location is requested only for a rule that lists networks`(_ policy: OnDemandPolicy, _ prompts: Int) async {
            let location = FakeLocation(status: .notDetermined)
            let rig = await makeRig(location: location)
            var profile = TunnelProfile(name: "Fixture")
            profile.onDemand = policy
            rig.relay.profileWillBeSavedOrArmed(profile)
            await quiet(rig)
            #expect(location.prompts == prompts)
            rig.stop()
        }

        @Test
        func `an already decided Location is not asked again`() async {
            for decided in [MacLocationStatus.authorised, .denied] {
                let location = FakeLocation(status: decided)
                let rig = await makeRig(location: location)
                var profile = TunnelProfile(name: "Fixture")
                profile.onDemand = .interfaces(.wifiOnly(.onlySSIDs(["Home"])))
                rig.relay.profileWillBeSavedOrArmed(profile)
                await quiet(rig)
                #expect(location.prompts == 0)
                rig.stop()
            }
        }

        @Test
        func `starting the relay never prompts`() async {
            let location = FakeLocation(status: .notDetermined)
            let rig = await makeRig(location: location)
            await quiet(rig)
            #expect(location.prompts == 0)
            rig.stop()
        }

        // MARK: Add connected network

        @Test
        func `add connected asks when undecided then reads the default interface`() async {
            let location = FakeLocation(status: .notDetermined, promptAnswer: .authorised)
            let rig = await makeRig(location: location)
            #expect(await rig.relay.connectedNetwork() == .ssid("Home"))
            #expect(location.prompts == 1)
            rig.stop()
        }

        @Test(arguments: [
            (MacLocationStatus.denied, MacWiFiRead.ssid("Home"), ConnectedNetworkReading.notAuthorised),
            (.authorised, .notAssociated, .notAssociated),
            (.authorised, .unreadable, .unreadable),
            (.authorised, .ssid(String(repeating: "x", count: 40)), .unreadable),
        ])
        func `add connected reports why it cannot`(
            _ status: MacLocationStatus, _ read: MacWiFiRead, _ expected: ConnectedNetworkReading,
        ) async {
            let rig = await makeRig(location: FakeLocation(status: status))
            rig.wifi.reading = read
            #expect(await rig.relay.connectedNetwork() == expected)
            rig.stop()
        }

        @Test
        func `add connected without Wi-Fi hardware is not associated`() async {
            let rig = await makeRig()
            rig.wifi.defaultInterfaceName = nil
            #expect(await rig.relay.connectedNetwork() == .notAssociated)
            rig.stop()
        }

        // MARK: Through the client

        @Test
        func `a daemon request reaches the client stream and the report leaves as reportWiFiNetwork`() async throws {
            let transport = RelayTransport()
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let relay = MacOnDemandRelay(
                requests: { await client.wifiNetworkRequests() }, subscriptions: { AsyncStream { $0.finish() } },
                location: FakeLocation(), wifi: FakeWiFi(), clock: { 9 },
                report: { try await client.reportWiFiNetwork($0) },
            )
            _ = try await client.connect()
            let task = Task { await relay.run() }
            for _ in 0 ..< 100 {
                await Task.yield()
            }
            await transport.deliver(.wifiNetworkRequested(interfaceName: "en0"))
            for _ in 0 ..< 2000 {
                if await !transport.requests.isEmpty {
                    break
                }
                await Task.yield()
            }
            let sent = await transport.requests
            #expect(sent.contains(.reportWiFiNetwork(WiFiObservation(
                interfaceName: "en0",
                reading: .ssid("Home"),
                observedAtContinuous: 9,
            ))))
            task.cancel()
            await client.disconnect()
        }
    }

    private actor RelayTransport: XPCTransport {
        private var callbacks: XPCClientCallbacks?
        private(set) var requests: [Request] = []

        func connect(callbacks: XPCClientCallbacks) {
            self.callbacks = callbacks
        }

        func invalidate() {
            callbacks = nil
        }

        func deliver(_ event: Event) async {
            guard let bytes = try? WireCodec.encode(event) else { return }
            await callbacks?.event(bytes)
        }

        func send(_ envelope: Data, secrets _: Data?) async throws -> Data {
            let request = try Envelope.decode(envelope).body
            if case .reportWiFiNetwork = request {
                requests.append(request)
            }
            switch request {
            case .hello:
                return try WireCodec.encode(Reply.hello(.init(
                    daemonVersion: "1", daemonBuild: 10, protocolVersion: Envelope.currentProtocolVersion, minimumClientBuild: 1,
                )))
            case .status: return try WireCodec.encode(Reply.status(.idle))
            default: return try WireCodec.encode(Reply.ok)
            }
        }
    }
#endif
