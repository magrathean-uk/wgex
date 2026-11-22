// SPDX-License-Identifier: MIT

import SwiftUI
import WidgetKit

/// Live Activity extension entry point.
@main
public struct WGEXLiveActivityBundle: WidgetBundle {
    /// Creates the bundle.
    public init() {}

    /// The bundle's widgets.
    public var body: some Widget {
        TunnelLiveActivity()
    }
}
