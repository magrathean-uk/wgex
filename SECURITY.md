# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories
("Report a vulnerability" on the repository's Security tab). Do not open a
public issue for a suspected vulnerability.

Include the affected version or commit, the platform, reproduction steps and
the impact you observed. Never include real private keys or live
configurations; use freshly generated test keys.

## Supported versions

WGEX is pre-alpha. Only the `main` branch receives fixes.

## Telemetry

WGEX collects no telemetry, analytics or crash reports, and it performs no
update check: the Updates tab says update checks are not available, its toggle is
fixed off and Sparkle is not linked. Some traffic besides your tunnel is
deliberate, for example endpoint name resolution over the underlay network; see
[`docs/protection-semantics.md`](docs/protection-semantics.md) for the exceptions.
