// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    import Foundation
    import WGEXDaemonCore

    public extension LabGuard {
        /// Bounded fixture hook decoder, absent from production.
        static let maximumMarkerSize = 64 * 1024
        func labHooks(marker: any LabMarkerInspecting) -> LabHooks? {
            guard isLabHost(), let data = marker.contents(atPath: Self.markerPath, limit: Self.maximumMarkerSize) else {
                return nil
            }
            if data.allSatisfy({ $0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }) {
                return LabHooks()
            }
            return try? JSONDecoder().decode(LabHooks.self, from: data)
        }
    }
#endif
