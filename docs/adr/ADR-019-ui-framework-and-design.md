# ADR-019 UI framework and design

Status: Accepted 2026-10-25

As revision 1, corrected for the 27 SDKs: `toolbarMinimizationBehavior(.onScrollDown, for: .navigationBar)` on iOS only (unavailable on macOS); `reorderable()` wrapped in `#if !os(tvOS)`; `backgroundExtensionEffect` only under split-view sidebars, not on the iPhone status tab; `.crossFade` on iOS/tvOS only; state colours are system semantic colours (`.green`, `.orange`, `.red`) with asset-catalogue high-contrast overrides, so Increase Contrast and vibrancy track the system; an **app-wide motion specification** (zoom navigation transitions from rows and cards, sheets morphing from their buttons, symbol replace effects, numeric text transitions, Reduce Motion fades) is part of `06-design-system.md`; snapshot gates for glass surfaces use XCUITest screenshots in simulators (ImageRenderer cannot render system glass), ImageRenderer only for non-glass components.

