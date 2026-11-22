# ADR-026 Tunnel lifetime on macOS

Status: Accepted 2026-10-25

As revision 1 (tunnel survives app quit; logout stops non-start-before-login tunnels and remembers the intent; Lockdown persists), implemented by `LoginSessionMonitor` (P4-21). Logout without Lockdown leaves traffic unprotected; this is in the known-gaps list.

