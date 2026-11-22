// SPDX-License-Identifier: MIT

#if os(macOS)
    import CoreWLAN
    import Foundation

    /// What CoreWLAN returned for one interface, before the relay folds in Location authorisation.
    public enum MacWiFiRead: Sendable, Equatable {
        case ssid(String)
        case notAssociated
        /// No usable name: redacted, or not valid UTF-8.
        case unreadable
    }

    /// Seam over CoreWLAN so tests supply readings and change events.
    @MainActor
    public protocol MacWiFiReading: AnyObject {
        /// BSD name of the default Wi-Fi interface; nil on a Mac without Wi-Fi.
        var defaultInterfaceName: String? { get }
        func read(interfaceName: String) -> MacWiFiRead
        /// Interface names whose SSID, link or power changed (CoreWLAN event monitoring).
        func changes() -> AsyncStream<String>
    }

    /// The production adapter: `CWWiFiClient` reads and event monitoring. The SSID never reaches a log from here.
    @MainActor
    public final class MacWiFiReader: NSObject, MacWiFiReading {
        private let client = CWWiFiClient.shared()
        private var observers: [UUID: AsyncStream<String>.Continuation] = [:]
        private var monitoring = false

        override public init() {
            super.init()
        }

        public var defaultInterfaceName: String? {
            client.interface()?.interfaceName
        }

        public func read(interfaceName: String) -> MacWiFiRead {
            guard let interface = client.interface(withName: interfaceName) else { return .notAssociated }
            if let ssid = interface.ssid() {
                return .ssid(ssid)
            }
            // `ssid()` is nil when unassociated, redacted, or the bytes are not UTF-8.
            if interface.ssidData() != nil {
                return .unreadable
            }
            return interface.rssiValue() == 0 && interface.transmitRate() == 0 ? .notAssociated : .unreadable
        }

        public func changes() -> AsyncStream<String> {
            let id = UUID()
            let (stream, continuation) = AsyncStream<String>.makeStream(bufferingPolicy: .bufferingNewest(8))
            observers[id] = continuation
            startMonitoring()
            continuation.onTermination = { [weak self] _ in
                Task { @MainActor in self?.removeObserver(id) }
            }
            return stream
        }

        private func removeObserver(_ id: UUID) {
            observers.removeValue(forKey: id)
            if observers.isEmpty, monitoring {
                try? client.stopMonitoringAllEvents()
                monitoring = false
            }
        }

        private func startMonitoring() {
            guard !monitoring else { return }
            client.delegate = self
            do {
                try client.startMonitoringEvent(with: .ssidDidChange)
                try client.startMonitoringEvent(with: .linkDidChange)
                try client.startMonitoringEvent(with: .powerDidChange)
                monitoring = true
            } catch {
                try? client.stopMonitoringAllEvents()
            }
        }

        fileprivate func deliver(_ interfaceName: String) {
            for observer in observers.values {
                observer.yield(interfaceName)
            }
        }
    }

    extension MacWiFiReader: CWEventDelegate {
        public nonisolated func ssidDidChangeForWiFiInterface(withName interfaceName: String) {
            Task { @MainActor in self.deliver(interfaceName) }
        }

        public nonisolated func linkDidChangeForWiFiInterface(withName interfaceName: String) {
            Task { @MainActor in self.deliver(interfaceName) }
        }

        public nonisolated func powerStateDidChangeForWiFiInterface(withName interfaceName: String) {
            Task { @MainActor in self.deliver(interfaceName) }
        }
    }
#endif
