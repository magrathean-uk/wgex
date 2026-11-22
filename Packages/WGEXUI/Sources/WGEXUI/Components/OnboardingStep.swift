// SPDX-License-Identifier: MIT

import SwiftUI

/// A button in an onboarding step.
public struct OnboardingAction {
    /// Title.
    public let title: String
    /// What it does.
    public let perform: () -> Void

    /// Creates an action.
    public init(_ title: String, perform: @escaping () -> Void) {
        self.title = title
        self.perform = perform
    }
}

/// One onboarding screen: step indicator, title, body, optional accessory
/// (for example a ``ServiceStateCard``), a prominent primary action and an
/// optional secondary action.
public struct OnboardingStep<Accessory: View>: View {
    private let title: String
    private let message: String
    private let index: Int
    private let count: Int
    private let primary: OnboardingAction
    private let secondary: OnboardingAction?
    private let accessory: Accessory

    /// Creates a step; `index` is 1-based.
    public init(
        title: String,
        message: String,
        index: Int,
        count: Int,
        primary: OnboardingAction,
        secondary: OnboardingAction? = nil,
        @ViewBuilder accessory: () -> Accessory,
    ) {
        self.title = title
        self.message = message
        self.index = index
        self.count = count
        self.primary = primary
        self.secondary = secondary
        self.accessory = accessory()
    }

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.extraLarge) {
            StepIndicator(index: index, count: count)
            VStack(alignment: .leading, spacing: Spacing.medium) {
                Text(title)
                    .font(.largeTitle.weight(.bold))
                    .accessibilityAddTraits(.isHeader)
                Text(message)
                    .font(Typography.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            accessory
            Spacer(minLength: 0)
            VStack(spacing: Spacing.medium) {
                Button(primary.title, action: primary.perform)
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                if let secondary {
                    Button(secondary.title, action: secondary.perform)
                        .buttonStyle(.glass)
                }
            }
            .frame(maxWidth: .infinity)
        }
        .padding(Spacing.glassPadding)
    }
}

/// Copy shared by onboarding steps.
public nonisolated enum OnboardingCopy {
    /// "Step 2 of 7".
    public static func stepLabel(index: Int, count: Int) -> String {
        MacStrings.stepOf(String(index), String(count))
    }
}

public extension OnboardingStep where Accessory == EmptyView {
    /// Creates a step without an accessory.
    init(title: String, message: String, index: Int, count: Int, primary: OnboardingAction, secondary: OnboardingAction? = nil) {
        self.init(title: title, message: message, index: index, count: count, primary: primary, secondary: secondary) {
            EmptyView()
        }
    }
}

private struct StepIndicator: View {
    let index: Int
    let count: Int

    var body: some View {
        HStack(spacing: Spacing.extraSmall) {
            ForEach(1 ... max(count, 1), id: \.self) { step in
                Capsule()
                    .fill(step == index ? AnyShapeStyle(.tint) : AnyShapeStyle(.quaternary))
                    .frame(width: step == index ? Spacing.extraLarge : Spacing.small, height: Spacing.small)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(OnboardingCopy.stepLabel(index: index, count: count))
    }
}
