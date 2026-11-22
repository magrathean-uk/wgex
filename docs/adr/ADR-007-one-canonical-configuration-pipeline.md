# ADR-007 One canonical configuration pipeline

Status: Accepted 2026-10-25

**Decision.** As revision 1: `WGEXCore` holds the single bounded parser and serialiser (policy and caps unchanged: hooks, `Table`, `FwMark`, `SaveConfig` and AmneziaWG keys rejected with named diagnostics; invalid prefixes rejected; limits 256 KiB, 4096 lines, 1024 peers, 4096 AllowedIPs, 64 DNS, 128-char names). The parser consumes UTF-8 byte views, never a `String` of the whole file, and the original text is retained with secret placeholders. Additional diagnostics: `keyInUseElsewhere` (public key already installed), `carrierRequiresSinglePeer`, `keepaliveClampedByCarrier`, `ipv6PolicyRequired`.

