import WGEXTesting
#if DEBUG || WGEX_LAB_BUILD
    import Foundation
#else
    import WGEXTesting
#endif
#if DEBUG
    import Foundation
#elseif os(macOS)
    import WGEXTesting
#endif
