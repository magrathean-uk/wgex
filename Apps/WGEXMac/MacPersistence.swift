// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore
    import WGEXProfileStore
    import WGEXUI

    /// Serial preference-file persistence shared by the app composition.
    @MainActor
    public final class MacPersistence {
        /// The public profile and settings store.
        public let store: ProfileStore
        private let extraURL: URL
        /// Set for good once an uninstall removes the app's data: a later save would recreate the deleted container.
        public private(set) var writesSuspended = false
        private var activeSaves = 0
        private var drained: [CheckedContinuation<Void, Never>] = []
        /// Uses an app-specific container; tests pass session scratch. The Mac admits tunnels saved without an address or a
        /// server (DEC-088); they load like any other and are never installed in the daemon until complete.
        public init(container: URL, simulated _: Bool) {
            store = ProfileStore(container: container, admitsIncomplete: true)
            extraURL = container.appendingPathComponent("mac-preferences.json")
        }

        /// Loads cached daemon settings and scene preferences independently of profile enumeration.
        public func load() async throws -> MacPreferences {
            var preferences = MacPreferences()
            if FileManager.default.fileExists(atPath: extraURL.path) {
                preferences = try JSONDecoder().decode(MacPreferences.self, from: Data(contentsOf: extraURL))
            }
            // A damaged daemon cache must not discard successfully decoded app-only preferences.
            if let settings = try? await store.loadSettings() {
                preferences.global = settings.macGlobal
                preferences.flags = settings.app.featureFlags
            }
            return preferences
        }

        /// Persists the current acknowledged cache and app-only preferences. After `suspendWrites()` it writes nothing.
        public func save(_ preferences: MacPreferences) async throws {
            guard !writesSuspended else { return }
            activeSaves += 1
            defer { saveEnded() }
            try await store.saveSettings(SettingsDocument(macGlobal: preferences.global, app: AppSettings(featureFlags: preferences.flags)))
            try FileManager.default.createDirectory(at: extraURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(preferences).write(to: extraURL, options: .atomic)
        }

        /// Refuses every later save and returns once the saves already writing have finished (M05-T10), so removing the
        /// container afterwards leaves nothing behind for a pending or debounced preference write to recreate.
        public func suspendWrites() async {
            writesSuspended = true
            guard activeSaves > 0 else { return }
            await withCheckedContinuation { drained.append($0) }
        }

        private func saveEnded() {
            activeSaves -= 1
            guard activeSaves == 0 else { return }
            let waiting = drained
            drained = []
            for continuation in waiting {
                continuation.resume()
            }
        }
    }

#endif
