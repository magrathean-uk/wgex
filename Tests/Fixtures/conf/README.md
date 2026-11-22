# `.conf` test vectors

Standard wg-quick files built from the keys in `../keys/` (all test fixtures,
see `../keys/README.md`). Addresses use documentation ranges (`192.0.2.0/24`,
`2001:db8::/32`), `example.test` and private `10.77.0.0/16` / `fd77:77::/32`
space, so nothing here can reach a real network. Each file starts with
`# WGEX TEST FIXTURE - NOT A REAL KEY`.

| File | Client key | Purpose | Expected result |
|---|---|---|---|
| `single-peer-full-tunnel.conf` | client1 | one peer, PSK, `0.0.0.0/0`, DNS, keepalive 25, IPv4 endpoint | accepted; full-tunnel IPv4 |
| `multi-peer-split.conf` | client1 | two peers, split `AllowedIPs`, hostname endpoint and IPv4 endpoint, `ListenPort`, `MTU`, two DNS servers | accepted; split tunnel; one peer without PSK |
| `ipv6-dual-stack.conf` | client2 | dual-stack `Address` and `DNS`, `0.0.0.0/0, ::/0`, bracketed IPv6 endpoint, `MTU` 1380 | accepted |
| `with-hooks-rejected.conf` | client1 | `PostUp` and `PreDown` shell hooks (harmless `echo`) | accepted with ignored-setting warnings; nothing is executed |
| `amnezia-fields-rejected.conf` | client1 | Amnezia fields `Jc Jmin Jmax S1 S2 H1 H2 H3 H4` | rejected as non-standard fields |
| `crlf-bom.conf` | client1 | UTF-8 BOM (`EF BB BF`) and CRLF line endings, otherwise equal to a simple full-tunnel file | accepted; BOM and CR are not part of any value |
| `comments-and-whitespace.conf` | client1 | mixed-case section and key names, no spaces around `=`, leading whitespace, trailing `#` comment, blank lines, spaces around the `,` in `AllowedIPs` | accepted; keys and values parsed exactly |
| `server-two-peers.conf` | server | server side for the test peer: two peers (client1 with PSK, client2 dual-stack) | accepted; used with `testpeer --key-file` |

"Accepted" and "rejected" describe the WGEX configuration pipeline (ADR-007);
parser tickets (P2-03) turn these into assertions. The `.conf` files are not
scanned by the secret scanner (it scans Swift, Go and YAML sources) and the
keys inside are fixtures.

M1-14: `interop-repeated-{address,dns,allowedips}.conf` accumulate values in file order.
`interop-ignored-{table,fwmark,saveconfig,preup,postup,predown,postdown}.conf` are accepted with
`warning/unsupportedSetting` diagnostics; these directives are never executed or applied. The
legacy `with-hooks-rejected.conf` filename is retained for corpus compatibility; it now warns.
