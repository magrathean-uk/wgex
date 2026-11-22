# Protection semantics (what the UI may claim)

| Claim | macOS | iOS/iPadOS | tvOS |
|---|---|---|---|
| Protected | Routes, DNS key, pf connected policy verified, canary hit, engine up | NE settings applied; on-demand armed | NE settings applied; on-demand armed |
| Blocked | pf connecting/error/lockdown verified and canary hit | Only lifecycle states measured as blocking by P4-13a with `includeAllNetworks` on | never claimed |
| Unprotected | Disconnected, no lockdown; manual stop | Disconnected or manual stop | Disconnected |
| Captive window | Routes and DNS withdrawn, narrowed pass-out, countdown | not available | not available |
| Unknown | Verification failed, canary not hit, pf disabled, stock anchor missing, secure install pending | Settings pending | Settings pending |

Known gaps: macOS early-boot window until the daemon's first enforcing status; pf pass rules persist while the daemon is dead (captive window); logout without Lockdown leaves traffic unprotected; Apple services that bypass routing on some macOS builds; iOS `includeAllNetworks` update lockout and real-IP leak during updates; CarPlay/Personal Hotspot with local sharing on, local DNS/mDNS with it off; tvOS no kill switch; trusted Wi-Fi names can be imitated; LAN allowance; tunnel exclusions (below); interim admin-to-root exposure before secure install.

## Tunnel exclusions

A tunnel can list addresses, CIDR ranges (IPv4 and IPv6) and host names whose traffic leaves on the physical network instead of the tunnel while the tunnel is up. Excluded traffic also bypasses the kill switch, as local traffic does when local network is allowed, and the Protection page says so.

- **macOS:** the excluded ranges are cut out of the tunnel's routes, so excluded traffic follows the Mac's own default route; no route names the router, so a router change needs no route change. The packet filter passes traffic sent to an excluded range, and traffic received from one, on the physical interface in every blocking state of that tunnel, except DNS (ports 53 and 853), which stays blocked there. An excluded range that contains the Mac's own address does not open anything else: traffic from that address to a destination outside the exclusions stays blocked.
- **iPhone, iPad and Apple TV:** the ranges become the tunnel's excluded routes.
- **Force all traffic (iPhone and iPad):** iOS ignores excluded routes while Force all traffic is on, so exclusions are not applied then: all traffic stays in the tunnel. WGEX keeps the Force all traffic setting as it is and still starts the tunnel; checking the tunnel gives a warning, and the tunnel's status says "Exclusions are not applied while Force all traffic is on." Turn Force all traffic off for the exclusions to apply.
- **Host names** are looked up on the physical network when the tunnel starts, and again on reconnect and network change (macOS). A name that cannot be looked up is shown as a warning; its traffic stays in the tunnel and the tunnel still starts.
- **DNS:** apps still look excluded names up through the tunnel's DNS, so no name leaks to the local network. A service that answers differently by location can give apps an address that WGEX did not exclude; that traffic then stays in the tunnel. Exclude the address range instead when this matters.
- **Limits:** up to 64 entries; no entry may cover every address, the tunnel's own address, its DNS servers or its server.

### Local ports (macOS)

A tunnel can also list local ports, for an app that binds itself to the physical network interface, such as a torrent client set to use `en0` and listening on port 1911. Entries are a port (`1911`, TCP and UDP), a port with a protocol (`1911/tcp`, `51413/udp`) or an inclusive range (`6881-6889/udp`).

- **Bind the app to the interface.** WGEX does not redirect anything: it adds no address translation for ports. In the app, choose the physical interface (for example `en0`, Wi-Fi or Ethernet) as its network interface; an app that is not bound to it keeps sending through the tunnel, where the kill switch still applies.
- **Routes (IPv4 only).** An app bound to the physical interface has no route of its own while a tunnel holds the default route. So while a tunnel with listed ports is up, the daemon adds two IPv4 routes (`0.0.0.0/1` and `128.0.0.0/1`) on the physical interface through its router, and removes them when the tunnel goes down or the ports are removed. That lets a bound app reach the network under a full tunnel.
- **IPv6 has no such route yet.** On an IPv6 full tunnel, a bound app on a listed port cannot reach IPv6 destinations.
- **What passes:** while the kill switch is on, the packet filter passes the listed ports and protocols on the physical interface, outbound from that interface's own addresses and inbound to them, IPv4 and IPv6, in every blocking state of that tunnel. Nothing sent from the tunnel address passes there, DNS (ports 53 and 853) stays blocked, and the passes keep no state, so removing a port or switching tunnel withdraws them at once.
- **Limits:** up to 16 port entries, ports 1 to 65535, at most 1024 ports per range, and never the tunnel's own listen port.
- **iPhone, iPad and Apple TV:** port exclusions are not supported. Port entries are kept in the tunnel but ignored, and the tunnel's status says they are not supported on this device.

### In configuration files

Exclusions travel in a WireGuard configuration as a whole-line comment in `[Interface]`, which the official WireGuard apps ignore:

```
[Interface]
PrivateKey = ...
Address = 10.64.0.2/32
# WGEX-Exclude = 192.0.2.0/24, 2001:db8::/32, 198.51.100.7, example.com, 1911, 6881-6889/udp
```

The key is not case sensitive, the line may repeat, and entries are separated by commas. WGEX writes it back on export, addresses first, then host names, then ports. A profile saved before ports existed has none.
