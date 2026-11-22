# ADR-001 Product, name, licence, trademark

Status: Accepted 2026-10-25

**Decision.** Product name **WGEX**; identifiers under `com.magrathean.WGEXApp` (ADR-016). "WireGuard" appears only descriptively; acknowledgements carry the trademark notice; a trademark review is P7-11. The code repository is **MIT**; every WGEX file carries `SPDX-License-Identifier: MIT`. Dependency policy: MIT, BSD-2/3, ISC, Apache-2.0 and Zlib may ship; MPL-2.0 only as isolated files in their own package with MPL headers and published source; GPL/LGPL/AGPL/Elastic/SSPL never ship. Test-only tools (sing-box server in Docker, gVisor netstack in the test peer and the Go test-support archive) are exempt because they are not distributed; `just check` proves the production archives contain neither. `THIRD_PARTY_NOTICES.md` and an SBOM are release artefacts.

**Rejected.** GPL-3 for the app (would allow copying Passepartout and sing-box; conflicts with App Store distribution and library reuse). Apache-2.0 (fine, but MIT matches the ecosystem).

