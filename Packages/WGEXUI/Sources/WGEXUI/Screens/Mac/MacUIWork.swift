// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Observation
    import SwiftUI
    import WGEXCore

    /// One app-owned coordinator for visibility, sampling and debounced writes.
    @MainActor
    public final class MacUIWork {
        private let shell: MacShellModel
        private let clock: MacUIClock
        private var displayTask: Task<Void, Never>?
        private var previousPhase: TunnelPhase?
        private var sessionGeneration: Generation?
        private let sampler: MacStatisticsSampler
        private var surfaces = Set<String>()
        private var preferencesTask: Task<Void, Never>?
        private var savedPreferences: MacPreferences?
        private var writeTask: Task<Bool, Never>?
        private var observing = false
        private var announcements = AccessibilityAnnouncementState()
        private let announce: (String) -> Void
        private var staleTask: Task<Void, Never>?
        private var captiveTask: Task<Void, Never>?
        private var lastReport: Date?
        private var captiveExpiry: Date?

        /// Uses the unchanged shell statistics request and preference writer.
        public init(
            shell: MacShellModel,
            clock: MacUIClock = MacUIClock(),
            sample: (() async -> Void)? = nil,
            announce: @escaping (String) -> Void = {
                AccessibilityNotification.Announcement($0).post()
            },
        ) {
            self.shell = shell
            self.clock = clock
            self.announce = announce
            sampler = MacStatisticsSampler(
                sleep: { try await clock.sleep(MacSessionTraffic.samplingInterval) },
                sample: sample ?? { await shell.sampleStatistics() },
            )
            shell.flushPreferences = { [weak self] in await self?.flushPreferences() }
        }

        /// A window or menu-extra presentation appeared, disappeared or became occluded.
        public func visibility(_ visible: Bool, surface: String) {
            if visible {
                surfaces.insert(surface)
            } else {
                surfaces.remove(surface)
            }
            shell.daemonHooks.visibility?(!surfaces.isEmpty)
            reconcileSampling()
            reconcileDisplayTick()
        }

        /// Status updates change eligibility without starting an idle timer.
        public func reconcileSampling() {
            let active = switch shell.status.phase {
            case .active, .reasserting, .captiveWindow: true
            case .idle, .preparing, .configuring, .stopping, .failed: false
            }
            sampler.update(visible: !surfaces.isEmpty, active: active)
        }

        /// Observes preferences once for the app, including changes made in transient scenes.
        public func observePreferences() {
            guard !observing else { return }
            observing = true
            savedPreferences = shell.preferences
            trackPreferences()
            trackStatus()
        }

        private func trackPreferences() {
            guard observing else { return }
            withObservationTracking {
                _ = shell.preferences
            } onChange: { [weak self] in
                Task { @MainActor in
                    self?.scheduleSave()
                    self?.trackPreferences()
                }
            }
        }

        private func trackStatus() {
            guard observing else { return }
            withObservationTracking {
                for message in announcements.messages(presentation: shell.designPresentation, toast: shell.operationMessage) {
                    announce(message)
                }
                trackSession()
                reconcileSampling()
                reconcileDisplayTick()
                reconcileDeadlines()
            } onChange: { [weak self] in
                Task { @MainActor in self?.trackStatus() }
            }
        }

        private func trackSession() {
            let phase = shell.status.phase
            defer { previousPhase = phase }
            if previousPhase == nil || (lastReport == nil && sessionGeneration == nil), case let .active(generation) = phase {
                sessionGeneration = generation
                return
            }
            if phase.generation != sessionGeneration, sessionGeneration != nil {
                shell.recordSessionStart(at: nil)
                sessionGeneration = nil
            }
            if case let .active(generation) = phase, previousPhase != nil, sessionGeneration != generation {
                shell.recordSessionStart(at: shell.lastStatusAt)
                sessionGeneration = generation
            }
        }

        private func reconcileDisplayTick() {
            let needsTime = shell.status.phase.generation != nil || shell.statistics != nil ||
                (shell.presentation.isStale && shell.lastReceivedReportAt != nil)
            guard !surfaces.isEmpty, needsTime else {
                displayTask?.cancel()
                displayTask = nil
                return
            }
            guard displayTask == nil else { return }
            shell.tick(at: clock.now())
            displayTask = Task { [shell, clock] in
                while !Task.isCancelled {
                    do { try await clock.sleep(1) } catch { return }
                    guard !Task.isCancelled else { return }
                    shell.tick(at: clock.now())
                }
            }
        }

        private func reconcileDeadlines() {
            if lastReport != shell.lastStatusAt {
                lastReport = shell.lastStatusAt
                staleTask?.cancel()
                if let lastReport {
                    staleTask = Task { [shell, clock] in
                        let delay = max(0, lastReport.addingTimeInterval(Staleness.threshold + 0.01).timeIntervalSince(clock.now()))
                        do { try await clock.sleep(delay) } catch { return }
                        shell.tick(at: clock.now())
                    }
                }
            }
            let expiry: Date? = if shell.simulated, case let .captiveWindow(expires) = shell.status.protection {
                expires
            } else {
                nil
            }
            if captiveExpiry != expiry {
                captiveExpiry = expiry
                captiveTask?.cancel()
                if let expiry {
                    captiveTask = Task { [shell, clock] in
                        do { try await clock.sleep(max(0, expiry.timeIntervalSince(clock.now()))) } catch { return }
                        shell.tick(at: clock.now())
                        await shell.closeExpiredCaptiveWindow()
                    }
                }
            }
        }

        private func scheduleSave() {
            guard writeTask == nil, savedPreferences != shell.preferences else { return }
            preferencesTask?.cancel()
            preferencesTask = Task { [weak self, clock] in
                if self?.shell.preferences.onboardingComplete != self?.savedPreferences?.onboardingComplete {
                    _ = await self?.saveIfNeeded()
                    return
                }
                do { try await clock.sleep(0.3) } catch { return }
                _ = await self?.saveIfNeeded()
            }
        }

        /// Joins an in-flight write and drains newer changes before application termination.
        public func flushPreferences() async {
            guard savedPreferences != nil else { return }
            preferencesTask?.cancel()
            while savedPreferences != shell.preferences {
                guard await saveIfNeeded() else { break }
            }
            preferencesTask?.cancel()
        }

        private func saveIfNeeded() async -> Bool {
            if let writeTask {
                return await writeTask.value
            }
            guard savedPreferences != shell.preferences else { return true }
            let snapshot = shell.preferences
            let task = Task { [self, shell] in
                let succeeded = await shell.savePreferences()
                if succeeded {
                    savedPreferences = snapshot
                }
                writeTask = nil
                if succeeded, shell.preferences != snapshot {
                    scheduleSave()
                }
                return succeeded
            }
            writeTask = task
            return await task.value
        }

        /// Stops pending UI work when the composition stops observing.
        public func stop() {
            observing = false
            shell.flushPreferences = nil
            lastReport = nil
            captiveExpiry = nil
            sampler.update(visible: false, active: false)
            preferencesTask?.cancel()
            staleTask?.cancel()
            captiveTask?.cancel()
            displayTask?.cancel()
            displayTask = nil
            surfaces = []
        }
    }

    public extension View {
        /// Display ages only while visible; the app coordinator owns semantic deadlines.
        func macStatusTime(_ shell: MacShellModel) -> some View {
            modifier(MacStatusTime(shell: shell))
        }
    }

    private struct MacStatusTime: ViewModifier {
        let shell: MacShellModel
        func body(content: Content) -> some View {
            content.environment(\.wgexDisplayDate, shell.now)
        }
    }
#endif
