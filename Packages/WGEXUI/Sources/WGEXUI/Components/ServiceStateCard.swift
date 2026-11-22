// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// Progress of the Mac background service through registration (plan 06
/// §4.1 onboarding step 3): Registered, Needs approval, Enabled, Running.
public nonisolated struct ServiceSetupProgress: Sendable, Hashable {
    /// State of one step.
    public enum StepState: String, Sendable, Hashable {
        /// Finished.
        case done
        /// In progress.
        case current
        /// Not reached yet.
        case pending
        /// Needs the user.
        case attention

        /// Spoken state.
        public var spoken: String {
            switch self {
            case .done: "done"
            case .current: MacStrings.inProgress
            case .pending: MacStrings.notStarted
            case .attention: MacStrings.needsAttention
            }
        }

        /// SF Symbol name.
        public var glyph: String {
            switch self {
            case .done: "checkmark.circle.fill"
            case .current: "circle.dotted"
            case .pending: "circle"
            case .attention: "exclamationmark.circle.fill"
            }
        }
    }

    /// One step.
    public struct Step: Sendable, Hashable, Identifiable {
        /// Stable identifier.
        public var id: String
        /// Title.
        public var title: String
        /// State.
        public var state: StepState
        /// Explanation when the step needs it.
        public var detail: String?
    }

    /// Steps in order.
    public let steps: [Step]
    /// Whether the user must approve the service in System Settings.
    public let needsApproval: Bool

    /// Derives the steps from the registration state and daemon liveness.
    public init(state: ServiceState, daemonRunning: Bool) {
        needsApproval = state == .requiresApproval
        steps = [
            Self.registeredStep(state),
            Step(
                id: "approval",
                title: needsApproval ? MacStrings.needsApproval : (state == .enabled ? MacStrings.approved : MacStrings.approval),
                state: needsApproval ? .attention : (state == .enabled ? .done : .pending),
                detail: needsApproval ? MacStrings.allowWGEXInSystemSettingsUnder : nil,
            ),
            Step(id: "enabled", title: MacStrings.enabled, state: state == .enabled ? .done : .pending, detail: nil),
            Step(
                id: "running",
                title: MacStrings.running,
                state: state == .enabled ? (daemonRunning ? .done : .current) : .pending,
                detail: state == .enabled && !daemonRunning ? MacStrings.waitingForTheBackgroundService : nil,
            ),
        ]
    }

    private static func registeredStep(_ state: ServiceState) -> Step {
        switch state {
        case .enabled, .requiresApproval:
            Step(id: "registered", title: MacStrings.registered, state: .done, detail: nil)
        case .notRegistered:
            Step(id: "registered", title: MacStrings.registered, state: .current, detail: MacStrings.registerTheBackgroundServiceTo)
        case .notFound:
            Step(
                id: "registered",
                title: MacStrings.registered,
                state: .attention,
                detail: MacStrings.theBackgroundServiceSLaunchd,
            )
        }
    }
}

/// Card showing the background service's registration and approval state,
/// with an action that opens System Settings when approval is needed.
public struct ServiceStateCard: View {
    private let progress: ServiceSetupProgress
    private let onOpenSettings: () -> Void

    /// Creates a card.
    public init(state: ServiceState, daemonRunning: Bool, onOpenSettings: @escaping () -> Void) {
        progress = ServiceSetupProgress(state: state, daemonRunning: daemonRunning)
        self.onOpenSettings = onOpenSettings
    }

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.medium) {
            Text(MacStrings.backgroundService)
                .font(Typography.cardTitle)
            ForEach(progress.steps) { step in
                HStack(alignment: .firstTextBaseline, spacing: Spacing.small) {
                    Image(systemName: step.state.glyph)
                        .foregroundStyle(step.state == .attention ? StateColor.blocked.color : .secondary)
                    VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                        Text(step.title)
                            .font(Typography.body)
                        if let detail = step.detail {
                            Text(detail)
                                .font(Typography.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .accessibilityElement(children: .ignore)
                .wgexAX(.service, "step", label: Self.accessibilityLabel(for: step), item: step.id)
            }
            if progress.needsApproval {
                Button(MacStrings.openSystemSettings, action: onOpenSettings).wgexControl(
                    .service,
                    "openSystemSettings",
                    label: MacStrings.openSystemSettings,
                )
                .buttonStyle(.glassProminent)
            }
        }
        .cardBackground()
    }

    /// "Registered: done. …".
    public static func accessibilityLabel(for step: ServiceSetupProgress.Step) -> String {
        MacStrings.namedValue(String(step.title), String(step.state.spoken)) + (step.detail.map { ". \($0)" } ?? "")
    }
}
