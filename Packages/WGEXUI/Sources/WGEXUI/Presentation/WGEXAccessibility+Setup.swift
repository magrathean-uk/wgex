// SPDX-License-Identifier: MIT

/// M07-T06 seam: identifiers of the setup sheet.
/// A `requiredAtLaunch` change is a retire plus a re-add.
public nonisolated extension WGEXAccessibility {
    /// Identifiers M07-T06 adds to ``catalogue``.
    static let setupEntries: [Entry] = [
        Entry(screen: .onboarding, id: "wgex.onboarding.openSystemSettings", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.serviceState", requiredAtLaunch: false),
        Entry(screen: .onboarding, id: "wgex.onboarding.registrationProblem", requiredAtLaunch: false),
    ]

    /// Base identifiers M07-T06 removes from ``catalogue``: setup has no Back button, start-up picker, Lockdown switch or
    /// refresh button any more (SPEC 7), and no Settings page uses them.
    static let setupRetired: Set<String> = [
        "wgex.onboarding.back",
        "wgex.onboarding.connectionAtStartup",
        "wgex.onboarding.lockdown",
        "wgex.onboarding.refreshServiceState",
    ]
}
