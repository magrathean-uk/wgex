# leakprobe

Host-testable receiver-based leak instrumentation; Swift 6.4, Swift 6 mode,
warnings as errors, no external dependencies. It opens ordinary UDP/TCP sockets.
It neither configures networking nor reads packets from an interface.

On the production Mac run **only** the loopback self-test and unit tests:

Build paths use the shared checkout resolver. From the repository root:

```sh
source Config/Scripts/lib.sh
swift build --package-path Tools/leakprobe --scratch-path "$(build_root)/spm/leakprobe"
swift test --package-path Tools/leakprobe --scratch-path "$(build_root)/spm/leakprobe"
swift run --package-path Tools/leakprobe --scratch-path "$(build_root)/spm/leakprobe" \
  leakprobe selftest --record "$(build_root)/leakprobe-selftest.json"
python3 -I Tools/lab/verdict.py "$(build_root)/leakprobe-selftest.json"
just test tools  # builds both guest helpers before the offline lab checks
```

The self-test binds 127.0.0.1 and ::1 on ephemeral, unprivileged ports. It sends
three rounds, 500 ms apart, and requires three DNS, HTTP, raw TCP and UDP receptions per
family: 18 sent plus 18 received observations. The no-tunnel result is
`unprotected`; that proves the harness record/receiver/verdict path, not a VPN.
A local listener avoids starting the userspace WireGuard peer or handling keys.

## VM CLI

Run the following commands only in the lab. Supply explicit numeric destination
addresses; the generator never uses system DNS, HTTP proxies or redirects.
The listener rejects wildcard addresses and sets IPV6_V6ONLY on IPv6 sockets.
Use one generator for all three destination classes: peer in-tunnel, LAN IPv4,
LAN IPv6. A gateway-resolver target can be added with scope `gateway`.

A configuration file has this shape (replace documentation addresses in the lab):

```json
{
  "format": "marker",
  "intervalMilliseconds": 500,
  "targets": [
    {"address":"10.77.0.1","scope":"in_tunnel","dnsPort":5354,"httpPort":8088,"udpPort":8088,"allowedLAN":false},
    {"address":"fd77:6765:7800::1","scope":"in_tunnel","dnsPort":5354,"httpPort":8088,"udpPort":8088,"allowedLAN":false},
    {"address":"192.0.2.20","scope":"outside_tunnel","dnsPort":5354,"httpPort":8088,"udpPort":8088,"allowedLAN":false},
    {"address":"2001:db8::20","scope":"outside_tunnel","dnsPort":5354,"httpPort":8088,"udpPort":8088,"allowedLAN":false}
  ]
}
```

`resolver` optionally overrides the numeric DNS destination; `httpHost` sets the
HTTP Host header independently of the destination. Ports must be nonzero.
DNS uses A or AAAA questions for `<nonce>.marker.wgex.test`; HTTP uses
`GET /marker/<nonce>`; UDP uses `WGEXLEAK <nonce>`. Set `format` to `leak` for
`<nonce>.leak.wgex.test` and `/leak/<nonce>`, matching the existing test peer.
Its marker DNS port is 5354, avoiding mDNSResponder's 5353; in-tunnel DNS also
listens on 53. Its source-scoped `--allow-udp-only-from` affects WireGuard outer
UDP, not these markers; do not replace it with a global UDP drop during relays.

```sh
# Lab receiver, explicit LAN addresses; TCP HTTP + UDP + DNS.
leakprobe listen --addresses 192.0.2.20,2001:db8::20 \
  --port 8088 --dns-port 5354 --seconds 30 --record lan-receiver.json
# Guest under test; 40 rounds at 500 ms intervals. A supplied nonce joins logs.
leakprobe generate --config probe.json --rounds 40 --state protected \
  --nonce lab-run-001 --record generator.json
```

The library `MarkerListener` can also be hosted at the peer's in-tunnel address.
Its DNS reply acknowledges the question without supplying an address; HTTP and
UDP use the explicitly configured IP, independent of DNS answers. No service
performs recursive resolution. Each observation records wall-clock timestamp,
nonce, protocol, family, destination address/port, scope and kind. Failed socket
operations are recorded; a send alone is never proof that a receiver saw it.

A run contains schemaVersion, nonce, canonical configurationSHA256, raw input
hashes, observations and externally assigned state windows. Windows are half-open
`[start,end)` Unix seconds. Synchronise VM/receiver clocks and keep boundary
uncertainty outside measured windows. Generator windows start with
`receiversComplete: false`. The lab coordinator merges receiver evidence. `verdict.py` computes coverage from per-binding listening intervals, matching configuration hashes and successful receiver controls. It ignores the legacy `receiversComplete` boolean; missing receivers, protocols, families or local socket failures mean `unknown`. Network timeout/connect failures can represent attempted blocked TCP probes.
Do not infer completeness from the app's status or from silence.

```sh
python3 -I Tools/lab/verdict.py generator.json \
  --receiver lan-receiver.json --receiver tunnel-receiver.json \
  --expectations Tools/lab/leak-expectations.json
```

Receiver files use the same record schema; they retain every received nonce.
Verdict selects the run nonce and measured windows. Existing testpeer JSONL logs
need conversion to these observations by the VM coordinator; no claim is made
that arbitrary peer event logs are accepted directly. Verdict hashes exact bytes
of the generator record, expectations table and each receiver input. Hashes give
reproducibility/integrity, not authentication of evidence. Exit codes: 0 all
expectations met; 1 leak or incomplete evidence; 2 malformed/unreadable input.

## Expectations

`Tools/lab/leak-expectations.json` transcribes the receiver-based state table:

| State | Required receiver evidence | Forbidden observations | Verdict when met |
| --- | --- | --- | --- |
| protected | DNS/HTTP/TCP/UDP in-tunnel, both families; LAN probes sent | Every outside marker, including gateway DNS | protected |
| blocked | LAN probes sent, both families; complete receiver coverage | Outside markers except explicitly configured allowed LAN HTTP/UDP | blocked |
| captiveWindow | Outside DNS and HTTP on 80/443, both families | UDP unless explicitly allowed LAN; other HTTP ports | unprotected |
| unprotected | Outside DNS/HTTP/TCP/UDP, both families | None | unprotected |
| unknown | No protection inference | None | unknown |

LAN exceptions require both window allowLAN and configuration target allowedLAN;
observations cannot grant themselves exceptions. DNS never gets an Allow LAN
exception. DHCP and NDP are unmarked infrastructure traffic and therefore not
misclassified as leaks by this marker-only tool. Test those separately in the VM.
Captive runs need HTTP port 80 or 443 and DHCP resolver destinations (53 for the
real rule); an ordinary 8088 marker service cannot prove the narrowed web pass.
Only matching configured destinations qualify. It is the lab coordinator's responsibility to run the web/resolver services and
use the console uid; the CLI does not change credentials or bind privileged ports.

## Guest capture - documentation only

These commands are for a disposable, guarded VM **only**. They were never run on
the production host. Replace utun7 with the guest's actual tunnel interface:

```sh
# VM only, separate guest terminals:
sudo tcpdump -ni en0 -w guest-underlay.pcap 'udp or tcp or icmp6'
sudo tcpdump -ni utun7 -w guest-tunnel.pcap 'udp or tcp or icmp6'
```

Still to measure in the VM: protected/blocked/captive state transitions; gateway
DNS with Allow LAN; external UDP from source port 68; tunnel-range traffic while
down; pre-existing connections; crash/update handoff; receiver liveness under
actual filtering. The host self-test establishes none of these protection claims.

## Automated Mac rows (M1-10)

`just lab verdict ROW` uses the Python ordinary-socket receiver on vmnet host 192.168.64.1 and the peer receiver on 10.77.0.1. `--dry-run` replays recorded marker fixtures without sockets or VM access; it never establishes live acceptance. The row catalogue, capability gaps, guest-only captures and orchestrator commands are in `Tests/Reports/M1/M1-10/README.md`. Raw TCP markers share the HTTP listener port and are distinguished by their payload.

M1-10 also issues `<nonce>-system.leak.wgex.test` via the guest system resolver, in an 8-second bounded subprocess, and inspects its en0 traffic with read-only host tcpdump. Direct DNS receiver probes remain separate. A compulsory unprotected tail proves guest delivery to the vmnet receivers; receiver self-controls establish binding and local processing. Sender coverage and received observations are ignored. Every verdict records familiesCovered; IPv6 capture inspection alone is not IPv6 end-to-end coverage. The netem row uses a 1500 ms TCP budget with overlapping rounds launched at 500 ms intervals.
