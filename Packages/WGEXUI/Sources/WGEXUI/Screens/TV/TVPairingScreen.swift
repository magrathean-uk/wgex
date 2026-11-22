// SPDX-License-Identifier: MIT

#if os(tvOS)
    import CoreImage
    import CoreImage.CIFilterBuiltins
    import SwiftUI

    public struct TVPairingScreen: View {
        @Bindable private var model: TVPairingModel
        public init(model: TVPairingModel) {
            self.model = model
        }

        public var body: some View {
            ScrollView {
                VStack(spacing: 32) {
                    Text("Add from iPhone or Mac").font(.largeTitle.bold())
                    content
                    if model.snapshot.stage != .completed {
                        Text("Expires in \(model.countdown)").monospacedDigit()
                            .accessibilityLabel("Pairing code expires in \(model.secondsRemaining) seconds")
                        Text("Attempts: \(model.snapshot.attempts) of 3").font(.footnote)
                        Button("New code") { Task { await model.newCode() } }.disabled(model.isBusy)
                    }
                }.padding(60).focusSection()
            }
            .task {
                await model.newCode()
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .milliseconds(250)) } catch { break }
                    await model.refresh()
                }
                await model.stop()
            }
            .onDisappear { Task { await model.stop() } }
            .confirmationDialog("Replace the existing profile?", isPresented: Binding(
                get: { model.snapshot.stage == .overwrite },
                set: {
                    if !$0 {
                        Task { await model.overwrite(false) }
                    }
                },
            ), titleVisibility: .visible) {
                Button("Replace existing", role: .destructive) { Task { await model.overwrite(true) } }
                Button("Cancel", role: .cancel) { Task { await model.overwrite(false) } }
            } message: { Text("A profile with this public key already exists. Its saved configuration will be replaced.") }
        }

        @ViewBuilder private var content: some View {
            switch model.snapshot.stage {
            case .waiting:
                TVPairingQR(payload: model.snapshot.payload)
                Text("Scan this QR in WGEX on your iPhone, or choose this Apple TV in WGEX on your Mac.")
            case .confirmSAS:
                Text("Confirm this code").font(.title2)
                if let sas = model.snapshot.sas {
                    Text(sas.prefix(3) + " " + sas.suffix(3)).font(.largeTitle.monospacedDigit())
                        .accessibilityLabel("Confirmation code " + sas.map(String.init).joined(separator: " "))
                }
                Text("Compare all six digits on both devices before accepting.")
                HStack {
                    Button("Accept") { Task { await model.confirm(true) } }.disabled(!model.canConfirm)
                    Button("Decline", role: .cancel) { Task { await model.confirm(false) } }
                }.focusSection()
            case .receiving: ProgressView("Receiving profile securely")
            case .overwrite: Text("Review the overwrite confirmation before continuing.")
            case .completed: Label("Profile received. Ready to connect.", systemImage: "checkmark.circle")
            case .expired: Text("This code has expired. Generate a new code to pair.")
            case .exhausted: Text("Three attempts were used. Generate a new code to pair.")
            case .failed: Text("Pairing failed. Check the other device or generate a new code.")
            case .stopped: Text("Pairing stopped")
            }
        }
    }

    private struct TVPairingQR: View {
        private static let context = CIContext()
        let payload: String
        var body: some View {
            Group {
                if let bitmap {
                    Image(decorative: bitmap, scale: 1).interpolation(.none).resizable().scaledToFit()
                        .padding(24).background(.white)
                } else {
                    Text("Preparing pairing code")
                }
            }
            .frame(width: 400, height: 400)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Pairing QR code. Scan with WGEX on your iPhone.")
        }

        private var bitmap: CGImage? {
            guard payload.hasPrefix("wgex-pair://v1/") else { return nil }
            let filter = CIFilter.qrCodeGenerator()
            filter.message = Data(payload.utf8); filter.correctionLevel = "M"
            guard let output = filter.outputImage else { return nil }
            return Self.context.createCGImage(output, from: output.extent)
        }
    }
#endif
