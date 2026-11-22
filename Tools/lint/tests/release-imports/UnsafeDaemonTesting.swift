// SPDX-License-Identifier: MIT
// Negative fixture (M1-15): a Release-reachable import of the daemon testing library must be caught.
import Foundation
#if DEBUG
import WGEXTesting
#endif
import WGEXDaemonCoreTesting
