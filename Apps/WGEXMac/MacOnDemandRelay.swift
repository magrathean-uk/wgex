// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXUI

    /// Relays the Wi-Fi network name to the daemon (ADR-030 section 3). The daemon evaluates the rules; this app only reads
    /// the SSID under Location authorisation and reports it with `reportWiFiNetwork`. The name is never logged or shown here.
    ///
    /// It reports on every `wifiNetworkRequested`, whatever it knows of the armed state, so a request cannot race the reply to
    /// `armOnDemand`. While the armed profile lists networks it also reports when the event subscription starts, on every
    /// CoreWLAN SSID, link or power change, and on every Location-authorisation change. An authorisation change reports for
    /// the interface the daemon last asked about, because the daemon accepts a report only for its Wi-Fi primary interface and
    /// CoreWLAN's default can differ from it; the default is used only before any request.
    @MainActor
    public final class MacOnDemandRelay {
        private let location: any MacLocationAuthorising
        private let wifi: any MacWiFiReading
        private let clock: () -> TimeInterval
        private let report: (WiFiObservation) async throws -> Void
        private let makeRequests: () async -> AsyncStream<String>
        private let makeSubscriptions: () async -> AsyncStream<Void>
        /// True while a profile the app armed holds an SSID list; supplied by the shell once it exists.
        public var armedWithSSIDList: () -> Bool = { false }
        /// The last well-formed interface the daemon asked for; what an authorisation-change report names.
        private var lastRequestedInterface: String?

        public init(
            requests: @escaping () async -> AsyncStream<String>, subscriptions: @escaping () async -> AsyncStream<Void>,
            location: any MacLocationAuthorising, wifi: any MacWiFiReading,
            clock: @escaping () -> TimeInterval, report: @escaping (WiFiObservation) async throws -> Void,
        ) {
            makeRequests = requests; makeSubscriptions = subscriptions
            self.location = location; self.wifi = wifi; self.clock = clock; self.report = report
        }

        /// Serves the relay until cancelled.
        public func run() async {
            let requests = await makeRequests()
            let subscriptions = await makeSubscriptions()
            let locationChanges = location.changes()
            let wifiChanges = wifi.changes()
            async let answers: Void = forward(requests) { await $0.send(interfaceName: $1, requested: true) }
            async let starts: Void = forward(subscriptions) { relay, _ in await relay.sendIfArmedWithList(interfaceName: nil) }
            async let wifiEvents: Void = forward(wifiChanges) { await $0.sendIfArmedWithList(interfaceName: $1) }
            async let locationEvents: Void = forward(locationChanges) { relay, _ in
                await relay.sendIfArmedWithList(interfaceName: relay.lastRequestedInterface)
            }
            _ = await (answers, starts, wifiEvents, locationEvents)
        }

        private func forward<Events: AsyncSequence & Sendable>(
            _ events: Events, _ action: (MacOnDemandRelay, Events.Element) async -> Void,
        ) async where Events.Element: Sendable {
            do {
                for try await event in events {
                    await action(self, event)
                }
            } catch {
                return
            }
        }

        /// Asks for Location when the profile's rule lists networks; SSID-free rules never prompt. Does not wait for the answer.
        public func profileWillBeSavedOrArmed(_ profile: TunnelProfile) {
            guard profile.onDemand.requiresSSID, location.status == .notDetermined else { return }
            Task { _ = await location.requestIfNeeded() }
        }

        /// "Add connected network": asks for Location if undecided, then reads the default Wi-Fi interface.
        public func connectedNetwork() async -> ConnectedNetworkReading {
            guard await location.requestIfNeeded() == .authorised else { return .notAuthorised }
            guard let name = wifi.defaultInterfaceName else { return .notAssociated }
            switch Self.sanitised(wifi.read(interfaceName: name)) {
            case let .ssid(value): return .ssid(value)
            case .notAssociated: return .notAssociated
            case .unreadable: return .unreadable
            }
        }

        /// The observation for one interface now; Location decides first, as ADR-030 section 3 requires.
        private func observation(interfaceName: String) -> WiFiObservation {
            let reading: WiFiReading = if location.status != .authorised {
                .notAuthorised
            } else {
                switch Self.sanitised(wifi.read(interfaceName: interfaceName)) {
                case let .ssid(value): .ssid(value)
                case .notAssociated: .notAssociated
                case .unreadable: .unreadable
                }
            }
            return WiFiObservation(interfaceName: interfaceName, reading: reading, observedAtContinuous: clock())
        }

        private func send(interfaceName: String, requested: Bool = false) async {
            let observation = observation(interfaceName: interfaceName)
            guard observation.isWellFormed else { return }
            if requested {
                lastRequestedInterface = interfaceName
            }
            // A refusal (not eligible, recovering, disconnected) is the daemon's decision; the next trigger reports again.
            try? await report(observation)
        }

        private func sendIfArmedWithList(interfaceName: String?) async {
            guard armedWithSSIDList(), let name = interfaceName ?? wifi.defaultInterfaceName else { return }
            await send(interfaceName: name)
        }

        /// A name outside 1 to 32 bytes cannot be a valid SSID for the wire.
        private static func sanitised(_ read: MacWiFiRead) -> MacWiFiRead {
            if case let .ssid(value) = read, !(1 ... 32).contains(value.utf8.count) {
                return .unreadable
            }
            return read
        }
    }
#endif
