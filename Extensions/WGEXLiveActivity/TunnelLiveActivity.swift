// SPDX-License-Identifier: MIT

import ActivityKit
import SwiftUI
import WGEXActivityShared
import WidgetKit

/// Placeholder Live Activity showing the profile name; phase 5 designs it.
public struct TunnelLiveActivity: Widget {
    /// Creates the widget.
    public init() {}

    /// The widget configuration.
    public var body: some WidgetConfiguration {
        ActivityConfiguration(for: TunnelActivityAttributes.self) { context in
            Text(verbatim: context.attributes.profileName)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.center) {
                    Text(verbatim: context.attributes.profileName)
                }
            } compactLeading: {
                Image(systemName: "lock.shield")
            } compactTrailing: {
                EmptyView()
            } minimal: {
                Image(systemName: "lock.shield")
            }
        }
    }
}
