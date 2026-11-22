// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
#if os(iOS)
    @preconcurrency import AVFoundation
    import SwiftUI
    import UIKit

    /// Why a scan produced no payload. The owner shows fixed copy for each; the camera never reports the code itself.
    public enum IOSScanFailure: Sendable, Equatable {
        case cameraDenied, cameraUnavailable, unreadable
    }

    /// Camera preview that reports the first QR payload, or a failure. Nothing is logged, stored or kept after delivery.
    public struct IOSQRScannerView: UIViewControllerRepresentable {
        private let onPayload: @MainActor (String) -> Void
        private let onFailure: @MainActor (IOSScanFailure) -> Void

        public init(
            onPayload: @escaping @MainActor (String) -> Void,
            onFailure: @escaping @MainActor (IOSScanFailure) -> Void,
        ) {
            self.onPayload = onPayload; self.onFailure = onFailure
        }

        public func makeUIViewController(context _: Context) -> IOSQRScannerController {
            IOSQRScannerController(onPayload: onPayload, onFailure: onFailure)
        }

        public func updateUIViewController(_: IOSQRScannerController, context _: Context) {}
    }

    @MainActor
    public final class IOSQRScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        private let onPayload: @MainActor (String) -> Void
        private let onFailure: @MainActor (IOSScanFailure) -> Void
        private let session = AVCaptureSession()
        private let queue = DispatchQueue(label: "wgex.qr-scanner")
        private var preview: AVCaptureVideoPreviewLayer?
        private var finished = false

        internal init(onPayload: @escaping @MainActor (String) -> Void, onFailure: @escaping @MainActor (IOSScanFailure) -> Void) {
            self.onPayload = onPayload; self.onFailure = onFailure
            super.init(nibName: nil, bundle: nil)
        }

        @available(*, unavailable) internal required init?(coder _: NSCoder) {
            fatalError("init(coder:) is not supported")
        }

        override public func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized: configure()
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                    Task { @MainActor in granted ? self?.configure() : self?.finish(.cameraDenied) }
                }
            default: finish(.cameraDenied)
            }
        }

        override public func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            preview?.frame = view.bounds
        }

        override public func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            stop()
        }

        private func configure() {
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input)
            else { return finish(.cameraUnavailable) }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return finish(.cameraUnavailable) }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            guard output.availableMetadataObjectTypes.contains(.qr) else { return finish(.cameraUnavailable) }
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            layer.frame = view.bounds
            view.layer.addSublayer(layer)
            preview = layer
            let session = session
            queue.async { session.startRunning() }
        }

        public nonisolated func metadataOutput(
            _: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from _: AVCaptureConnection,
        ) {
            let payload = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue
            MainActor.assumeIsolated {
                guard !finished else { return }
                if let payload, !payload.isEmpty {
                    finished = true; stop(); onPayload(payload)
                } else {
                    finish(.unreadable)
                }
            }
        }

        private func finish(_ failure: IOSScanFailure) {
            guard !finished else { return }
            finished = true; stop(); onFailure(failure)
        }

        private func stop() {
            let session = session
            queue.async {
                if session.isRunning {
                    session.stopRunning()
                }
            }
        }
    }
#endif
