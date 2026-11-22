// SPDX-License-Identifier: MIT

// Checked-in fallback for `swift build` and `swift test` inside the package.
// Xcode builds compile the generated file instead (WGEX_GENERATED_IDENTIFIERS
// is defined by Package.swift when Generated/BuildIdentifiers.generated.swift
// exists). The fallback always uses the development base, so a release build
// without the generated file is refused rather than shipped with `.dev`.
#if !WGEX_GENERATED_IDENTIFIERS
    #if !DEBUG
        #error("Release builds need Generated/BuildIdentifiers.generated.swift; run `just gen` or `just build`")
    #endif

    /// Values behind ``BuildIdentifiers/current`` when the generated file is absent.
    package enum BuildIdentifierSource {
        /// Development bundle identifier base (`WGEX_BUNDLE_ID_BASE` in Debug).
        package static let bundleIDBase = "com.magrathean.WGEXApp.dev"
        /// Apple Developer team identifier (`WGEX_TEAM`).
        package static let team = "ABCDE12345"
        /// False: these values come from the checked-in fallback.
        package static let isGenerated = false
    }
#endif
