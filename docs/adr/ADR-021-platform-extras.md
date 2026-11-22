# ADR-021 Platform extras

Status: Accepted 2026-10-25

**Decision.** iOS Live Activity with a truthful staleness model (`staleDate` 60 s, "Status unknown, open WGEX" stale view, no byte rates, timers for ages, shown for user sessions and attention states within the 8-hour cap, profile name hidden by default, provider-driven updates if spike P5-16a allows). **State notifications** (UserNotifications) on Mac and iOS for transitions to blocked, failed or unknown that the user did not initiate, rate-limited, with "Open WGEX" and "Disconnect" actions (P5-32). No Control Center controls, App Shortcuts, Siri, widgets or Watch.

