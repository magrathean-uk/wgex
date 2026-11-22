// SPDX-License-Identifier: MIT

#if os(macOS)
    import CoreLocation
    import Foundation

    /// Location authorisation as the on-demand relay needs it (ADR-030 section 3). Location is what gates the Wi-Fi network
    /// name; the app asks only when a profile lists networks or the user asks for "Add connected network".
    public enum MacLocationStatus: Sendable, Equatable {
        /// The user has not decided yet.
        case notDetermined
        case authorised
        /// Denied or restricted.
        case denied
    }

    /// Seam over `CLLocationManager` so tests drive each authorisation change.
    @MainActor
    public protocol MacLocationAuthorising: AnyObject {
        var status: MacLocationStatus { get }
        /// Shows the system prompt only while undecided, then returns the resulting status.
        func requestIfNeeded() async -> MacLocationStatus
        /// Every later authorisation change (`locationManagerDidChangeAuthorization`).
        func changes() -> AsyncStream<MacLocationStatus>
    }

    /// The production adapter. It creates no manager until asked, so launch never touches Location.
    @MainActor
    public final class MacLocationAuthorisation: NSObject, MacLocationAuthorising {
        private var manager: CLLocationManager?
        private var observers: [UUID: AsyncStream<MacLocationStatus>.Continuation] = [:]
        private var waiting: [CheckedContinuation<MacLocationStatus, Never>] = []

        override public init() {
            super.init()
        }

        public var status: MacLocationStatus {
            guard let manager else { return Self.map(CLLocationManager().authorizationStatus) }
            return Self.map(manager.authorizationStatus)
        }

        public func requestIfNeeded() async -> MacLocationStatus {
            guard status == .notDetermined else { return status }
            let manager = ensureManager()
            return await withCheckedContinuation { continuation in
                waiting.append(continuation)
                manager.requestWhenInUseAuthorization()
            }
        }

        public func changes() -> AsyncStream<MacLocationStatus> {
            let id = UUID()
            let (stream, continuation) = AsyncStream<MacLocationStatus>.makeStream(bufferingPolicy: .bufferingNewest(4))
            observers[id] = continuation
            _ = ensureManager()
            continuation.onTermination = { [weak self] _ in
                Task { @MainActor in self?.observers.removeValue(forKey: id) }
            }
            return stream
        }

        private func ensureManager() -> CLLocationManager {
            if let manager {
                return manager
            }
            let created = CLLocationManager()
            created.delegate = self
            manager = created
            return created
        }

        fileprivate func authorisationChanged() {
            let current = status
            for observer in observers.values {
                observer.yield(current)
            }
            if current != .notDetermined {
                let released = waiting
                waiting = []
                for continuation in released {
                    continuation.resume(returning: current)
                }
            }
        }

        private nonisolated static func map(_ status: CLAuthorizationStatus) -> MacLocationStatus {
            switch status {
            case .authorizedAlways, .authorizedWhenInUse: .authorised
            case .denied, .restricted: .denied
            case .notDetermined: .notDetermined
            @unknown default: .denied
            }
        }
    }

    extension MacLocationAuthorisation: CLLocationManagerDelegate {
        public nonisolated func locationManagerDidChangeAuthorization(_: CLLocationManager) {
            Task { @MainActor in self.authorisationChanged() }
        }
    }
#endif
