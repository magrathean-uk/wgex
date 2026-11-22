# ADR-010 pf implementation on macOS

Status: Accepted 2026-10-25

**Decision.** Sub-anchor `com.apple/wgex` loaded with `/sbin/pfctl` (fixed path, argv array, cleared environment, deadline), enabled with a journalled reference token, verified by read-back and by an **evaluation canary** (counting rule hit by a root datagram to TEST-NET) at start, after macOS build changes, on route/configd notifications and every 5 s while any blocking policy is active; `pfctl -d` by another party, a missing stock `anchor "com.apple/*"`, an earlier shadowing `quick` pass, or a changed anchor → `unknown` and re-assertion. Rules are all `quick`, never contain `set` lines, end with `block drop quick all`, and **states are killed per underlay interface** (`pfctl -i <if> -F states`, VM-verified; never a global flush). Per-release recording of sibling `com.apple/*` anchors and dynamically inserted Apple anchors. Insertion of the anchor into the main ruleset through `/dev/pf` ioctls is spike P4-24; if feasible with clean-room `pfvar` definitions it replaces the stock-anchor dependency, otherwise `unknown` remains the honest state on customised systems.

