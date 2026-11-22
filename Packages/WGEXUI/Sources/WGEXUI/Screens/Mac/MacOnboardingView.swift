// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// First-run setup (SPEC 7): three sheets on the main window with three progress dots. Welcome; Allow WGEX in the
    /// Background, whose Continue waits for macOS to report the service running; Add a Tunnel, the SPEC 6.1 content with
    /// "Not Now". Install checks, start-up and protection choices live on their own pages, not here.
    public struct MacOnboardingView: View {
        @Bindable private var model: MacShellModel
        private let finished: () -> Void
        private let addProfile: () -> Void
        private let paste: () -> Void
        private let createEmpty: () -> Void
        private let dropProfiles: ([URL]) -> Bool
        private let simulateApproval: () -> Void

        /// `finished` is "Not Now"; the step 3 rows and a dropped file leave setup and run the window's own Add actions.
        public init(
            model: MacShellModel,
            finished: @escaping () -> Void = {},
            addProfile: @escaping () -> Void = {},
            paste: @escaping () -> Void = {},
            createEmpty: @escaping () -> Void = {},
            dropProfiles: @escaping ([URL]) -> Bool = { _ in false },
            simulateApproval: @escaping () -> Void = {},
        ) {
            self.paste = paste; self.createEmpty = createEmpty; self.dropProfiles = dropProfiles
            self.model = model; self.finished = finished; self.addProfile = addProfile; self.simulateApproval = simulateApproval
        }

        public var body: some View {
            let step = model.onboardingStep
            VStack(alignment: .leading, spacing: 14) {
                Text(step.title).font(MacDesign.heading).lineLimit(1)
                switch step {
                case .welcome:
                    message(step)
                    footer { continueButton }
                case .backgroundService:
                    message(step)
                    serviceGroup
                    footer {
                        Button(MacStrings.openSystemSettingsEllipsis, action: model.openApproval)
                            .wgexControl(.onboarding, "openSystemSettings", label: MacStrings.openSystemSettingsEllipsis)
                            .disabled(model.hostGuarded)
                            .lineLimit(1).fixedSize()
                        continueButton
                    }
                case .addTunnel:
                    // The Add a Tunnel content shows its own text; its "Not Now" row shares a line with the dots.
                    MacAddTunnelView(
                        chooseFile: addProfile, paste: paste, createEmpty: createEmpty,
                        dismissTitle: MacStrings.notNow, dismiss: finished, showsHeading: false,
                    )
                    .overlay(alignment: Alignment(horizontal: .leading, vertical: .lastTextBaseline)) {
                        progressDots.alignmentGuide(.lastTextBaseline) { $0[VerticalAlignment.center] + 4 }
                    }
                }
            }
            .buttonStyle(.macSecondary)
            .padding(20).frame(width: 520, alignment: .leading)
            .background(MacDesign.pageBackground)
            .dropDestination(for: URL.self) { urls, _ in
                guard model.onboardingStep == .addTunnel, !urls.isEmpty else { return false }
                return dropProfiles(urls)
            }
            .accessibilityElement(children: .contain)
            .wgexAX(.onboarding, "surface", label: step.title)
            .overlay(alignment: .bottom) {
                if let message = model.operationMessage {
                    MacToast(message, dismiss: model.dismissMessage).padding(.bottom, 56).padding(.horizontal, 20)
                }
            }
        }

        private func message(_ step: MacOnboardingStep) -> some View {
            Text(step.message).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                .fixedSize(horizontal: false, vertical: true)
        }

        private func footer(@ViewBuilder _ buttons: () -> some View) -> some View {
            HStack(spacing: 8) {
                progressDots
                Spacer(minLength: 12)
                buttons()
            }
            .padding(.top, 6)
        }

        /// Display only: the filled dot is the current step.
        private var progressDots: some View {
            HStack(spacing: 6) {
                ForEach(MacOnboardingStep.ordered) { step in
                    Circle().fill(step == model.onboardingStep ? MacDesign.label : MacDesign.label3).frame(width: 7, height: 7)
                }
            }
            .accessibilityElement(children: .ignore)
            .wgexAX(.onboarding, "step", label: model.onboardingStep.progressLabel)
        }

        private var continueButton: some View {
            Button(MacStrings.continueLabel) { Task { await model.advanceOnboarding() } }
                .wgexControl(.onboarding, "continue", label: MacStrings.continueLabel)
                .buttonStyle(.macPrimary).keyboardShortcut(.defaultAction)
                .disabled(!model.canAdvance || model.busy)
                .lineLimit(1).fixedSize()
        }

        /// One grouped row, "Background service", with its state in words; a plain line and Register Again only when
        /// registration failed or macOS cannot find the service.
        private var serviceGroup: some View {
            let word = MacOnboardingStep.serviceWord(state: model.serviceState, running: model.daemonRunning)
            return VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(MacStrings.backgroundService).lineLimit(1)
                    Spacer(minLength: 12)
                    Text(word).foregroundStyle(MacDesign.label2).lineLimit(1).fixedSize()
                }
                .padding(.horizontal, 12).padding(.vertical, 9)
                .macCard(padding: 0)
                .accessibilityElement(children: .ignore)
                .wgexAX(.onboarding, "serviceState", label: MacStrings.backgroundService)
                .accessibilityValue(word)
                if let problem = model.setupServiceProblem {
                    Text(problem).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                        .fixedSize(horizontal: false, vertical: true)
                        .wgexAX(.onboarding, "registrationProblem", label: problem)
                }
                if model.setupOffersRegisterAgain || model.updateAvailable || (model.simulated && model.serviceState == .requiresApproval) {
                    HStack(spacing: 8) { serviceActions }
                }
            }
        }

        @ViewBuilder private var serviceActions: some View {
            if model.setupOffersRegisterAgain {
                Button(MacStrings.registerAgain) { Task { await model.registerFromSetup() } }
                    .wgexControl(.onboarding, "registerBackgroundService", label: MacStrings.registerAgain)
                    .disabled(model.busy)
                    .lineLimit(1).fixedSize()
            }
            if model.updateAvailable {
                Button(MacStrings.finishUpdateEllipsis) { Task { await model.finishUpdate() } }
                    .wgexControl(.service, "finishUpdate", label: MacStrings.finishUpdateEllipsis)
                    .disabled(model.hostGuarded || model.busy)
                    .lineLimit(1).fixedSize()
            }
            if model.simulated, model.serviceState == .requiresApproval {
                Button(MacStrings.simulateApproval, action: simulateApproval)
                    .wgexControl(.onboarding, "simulateApproval", label: MacStrings.simulateApproval)
                    .lineLimit(1).fixedSize()
            }
        }
    }
#endif
