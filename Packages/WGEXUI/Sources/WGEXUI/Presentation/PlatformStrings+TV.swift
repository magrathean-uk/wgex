// SPDX-License-Identifier: MIT

/// TV-specific disclosures used by shared UI and platform screens.
public nonisolated extension PlatformStrings {
    /// Copy used in the shared protection presenter.
    static let appleTVCannotEnforceAKillSwitch = "Apple TV cannot enforce a kill switch"
    /// Copy used in the shared profile editor string facade.
    static let qrUnavailableOnTV = "QR export is unavailable on Apple TV."

    /// Static TV copy covered by the catalogue tests.
    static let tvCatalogue: [String] = [
        appleTVCannotEnforceAKillSwitch, qrUnavailableOnTV,
    ]
}
