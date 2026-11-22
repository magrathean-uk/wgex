// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore
#if !os(tvOS)
    import CoreImage
    import CoreImage.CIFilterBuiltins
#endif

/// A local QR preview; secret bytes are released after rasterisation.
public struct QRCodeView: View {
    #if !os(tvOS)
        private let code: CGImage?
    #endif

    public init(payload: consuming SecretText) {
        #if !os(tvOS)
            code = Self.render(payload)
        #endif
    }

    public var body: some View {
        #if os(tvOS)
            ContentUnavailableView(EditorStrings.qrUnavailable, systemImage: "qrcode")
        #else
            if let code {
                Image(decorative: code, scale: 1)
                    .interpolation(.none).resizable().scaledToFit()
                    .padding(Spacing.large).background(.white)
                    .privacySensitive()
                    .accessibilityLabel(EditorStrings.qrWarning)
            } else {
                ContentUnavailableView(EditorStrings.qrTooLarge, systemImage: "qrcode")
            }
        #endif
    }

    #if !os(tvOS)
        private static func render(_ payload: borrowing SecretText) -> CGImage? {
            guard payload.byteCount <= 2953 else { return nil }
            var data = payload.bytes.withUnsafeBytes { Data($0) }
            defer { data.resetBytes(in: 0 ..< data.count) }
            let filter = CIFilter.qrCodeGenerator()
            filter.message = data; filter.correctionLevel = "L"
            guard let output = filter.outputImage else { return nil }
            // QR requires a quiet zone at least four modules wide, independent of view size.
            let extent = output.extent.insetBy(dx: -4, dy: -4)
            let white = CIImage(color: CIColor(red: 1, green: 1, blue: 1)).cropped(to: extent)
            let scaled = output.composited(over: white).transformed(by: CGAffineTransform(scaleX: 8, y: 8))
            return CIContext().createCGImage(scaled, from: scaled.extent)
        }
    #endif
}
