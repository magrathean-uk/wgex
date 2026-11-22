# macOS 26 VM lab

These scripts prepare the VM lab. They have been checked offline; the guest,
its registration, approval and the `approved` snapshot were done by the owner on 26 October 2026 (see "First registration and approval" below); no restore-to-SSH timing from step 10 is recorded here; later `ready*` snapshots follow the manual app path section. Nothing
here launches WGEX on the host. Run commands from the repository unless a
step explicitly says to use the guest terminal or the wrapper directory.

## One-time owner setup

1. Either clone a macOS 26 guest you already have: in the wrapper
   directory, `./vm-tart clone SOURCE_VM macos26-wgex`, where `SOURCE_VM` is a
   guest of your choosing, or use the IPSW route below. Hosts may run macOS 26.x
   or 27.x. Provisioning accepts guest ProductVersion 26.x; 27.x is also
   accepted with a note, but does not replace macOS 26 acceptance.
   Optional IPSW creation remains available: `bash Tools/lab/tart/create.sh`
   prints the plan; `--yes-download` explicitly enables creation. Add
   `--ipsw /absolute/path/to/macos26.ipsw` for approved local media. `latest`
   can change and may require about 25 GB. Creation sets 4 CPUs, 8192 MiB RAM
   and a 64 GB disk, and never boots the new guest automatically.
2. In `$WGEX_LAB_VM_ROOT`, run
   `./vm-tart run --vnc macos26-wgex`. Complete Setup Assistant with administrator
   `labuser`; use the lab login standard. Enable Remote Login in System Settings.
   Authorise the Mac key's public half in this guest user's `authorized_keys`.
   The private key stays on the Mac. Never put a password in a command or file.
3. Establish the lab standard of passwordless sudo inside the guest. If needed,
   open the **guest terminal**, use `sudo visudo -f
   /etc/sudoers.d/wgex-lab-bootstrap`, and enter
   `labuser ALL=(ALL) NOPASSWD: ALL`. This one interactive bootstrap uses the
   guest administrator password. Provisioning checks `sudo -n true`, then
   maintains a validated `/etc/sudoers.d/wgex-lab` entry. Remote Login must
   already work for SSH provisioning; provisioning also enables it explicitly.
   If macOS requires Full Disk Access for `systemsetup`, grant it in the guest
   and rerun provisioning; this has not been verified on the new guest.
4. Resolve the address through `./vm-tart ip --resolver arp macos26-wgex`, with
   `./vm-tart ip --resolver dhcp macos26-wgex` as fallback. Compare the guest's
   SSH host-key fingerprint in its terminal before accepting the key from the
   Mac. Set `K` to the private key you authorised (the same path as
   `WGEX_LAB_KEY`), then
   `ssh -F /dev/null -o IdentityAgent=none -i "$K" -o IdentitiesOnly=yes
   labuser@ADDRESS` for the first interactive connection. Automation requires
   an already trusted host key, key authentication and no SSH agent.
5. Run `bash Tools/lab/tart/provision.sh`. Enter a new password for the
   non-admin `tester` account on terminal stdin when prompted; terminal echo
   is disabled. Do not use a password literal, environment variable or file.
   The password goes through SSH stdin and a guest-only pipe to Directory
   Service; it never enters process arguments or a report. Existing `tester`
   accounts retain their passwords. Provisioning verifies the VM sysctl before
   creating a root-owned regular marker `/var/db/wgex-lab-host`, mode 0644,
   containing `{}`. It installs only capture helpers, enables Remote Login and
   creates no package dependencies. It fetches the provisioning report into
   `$WGEX_LAB_REPORTS/provisioning-report.txt` (default `.build/lab-reports/`).
6. Run `bash Tools/lab/tart/snapshot.sh clean`. This shuts down the guest cleanly,
   waits for stopped state, clones it to `macos26-wgex-clean`, restarts it and
   waits for guarded SSH readiness. Existing snapshot names are never replaced.
7. The Lab configuration and `just lab` dispatcher are integrated.
   `lab build` generates the project and invokes `xcodebuild -configuration Lab`
   without checking or contacting a VM. It uses
   `$(build_root)/derived-data`, disables package updates and
   writes a local hash receipt alongside the signed app. It never runs products.
   Lab inherits Debug, adds `WGEX_LAB_BUILD` to local package targets and uses
   the development bundle identifier. Release never defines the Lab condition.
8. In a fresh worktree run `just engine` once first: the engine binary and
   `Packages/WGEXEngine/Binary/provenance.json` are not tracked, and `just lab build`
   stops without them. Then run `just lab build`, then `just lab install` (or supply the absolute path to
   the built `WGEX.app` with its adjacent `.lab-build.sha256` receipt). Installation
   checks signatures and the receipt, transports a `ditto` archive over scp,
   extracts it inside the guest, checks its signature, and uses guest `ditto`
   to install it into `/Applications`. No re-signing takes place. The receipt
   records local build provenance; the Swift guard remains the runtime control.
9. In the guest GUI over VNC, launch the app, register the daemon, and approve it
   in System Settings. The scripts cannot grant this approval. Current Debug
   signing is ad hoc until the signing prerequisites are supplied; daemon
   authentication or approval may require those prerequisites before proceeding.
10. Run `bash Tools/lab/tart/snapshot.sh approved`. Preserve both snapshots.
    Run `just lab up` and check that the reported restore-to-guarded-SSH time is
    under 60 seconds, then run `just lab test smoke` and `just lab down`.

## Agent loop

After the one-time setup:

```sh
just lab up
just lab test smoke
just lab down
```

`up` restores `approved` and boots the working guest. Tests verify macOS 26 (27 is also accepted with a note),
`kern.hv_vmm_present == 1`, and a non-symlink, root-owned 0644 marker before
starting. Smoke reads the app's signature, short version and build version,
then reads `sudo -n pfctl -s info`. It does not register or launch anything.
The suite output is saved as `$WGEX_LAB_REPORTS/<UTC-date>-smoke.log`.
After a suite starts, its exit trap restores `approved` on success or failure;
`--keep` suppresses that reset. A failed initial guard never triggers destructive
reset. An unknown suite refuses. Restore failure makes the command fail.
Reset restarts the guest, so finish with `down`.

Other commands: `just lab ssh [-- command ...]`, `just lab snapshot NAME`,
`just lab restore NAME`, and `bash Tools/lab/tart/snapshot.sh list`.
Every restore clones the snapshot, which gives the guest a new MAC and address;
the guest host key is therefore pinned for the host-only subnet in
`$WGEX_LAB_VM_ROOT/wgex-known_hosts` (`-o UserKnownHostsFile`), written
once by `just lab trust` (trust on first use; compare the printed fingerprint
with the one accepted when the guest was provisioned). `~/.ssh/known_hosts` is
not used.
Restore validates that the source clone exists and is stopped before deleting
only the working VM. Snapshots are local Tart clones, never registry pulls.
Both snapshot and restore print elapsed time through guarded SSH readiness;
a restore of `approved` taking 60 seconds or more warns after guarded SSH succeeds.
Clone failure after deletion requires owner recovery from the preserved snapshot.

`just lab reset-btm --yes-reset` explicitly copies and invokes the guarded
`reset-btm.sh` inside the guest. This is the sole reset entry point; resetting
background tasks does not approve a daemon. It is never part of smoke.

## Driving the guest desktop

The guest always runs headless (DEC-112): `lab up` and every restore start it
with `--vnc-experimental --no-graphics`, so no Tart window opens on any host
display. Virtualization.framework's VNC server keeps the guest's display
attached, so guest screencapture and System Events keep working, and
`Tools/lab/console/console.py` types the console login and administrator
approval through it when `WGEX_LAB_VNC_FILE` names a private file for Tart's
address and one-time password (CI=1 keeps Tart from opening the host's Screen
Sharing app). `just lab gui` drives the desktop from SSH:

```sh
just lab gui shot "$TMPDIR/guest.png"   # screencapture inside the guest, copied out
just lab gui dump WGEX 1                 # accessibility tree of a window
just lab gui dump WGEX 1 wgex.protection.lockdown   # targeted walk: window line, first match, ax-walk target=found|missing
just lab gui click 192 546               # click at guest coordinates
just lab gui activate "System Settings"
just lab gui open-pane x-apple.systempreferences:com.apple.LoginItems-Settings.extension
just lab gui run open -a /Applications/WGEX.app
just lab gui seed-tcc                    # one-time, lab only; see below
```

`shot` captures inside the guest's console session; there is no host-window
fallback. Captures are refused inside the repository. Guest commands run as the console user through
`guest/asu.sh` (`launchctl asuser`); a reboot wipes the helpers from the guest,
so every `gui` call re-copies them to `~/lab/gui`.

TCC attributes an SSH session to `/usr/libexec/sshd-keygen-wrapper`, so System
Events and `screencapture` are refused until `guest/seed-tcc.sh` has inserted
allow rows (Accessibility, PostEvent, ListenEvent, ScreenCapture, Full Disk
Access, AppleEvents to System Events) for that binary and the tools it runs.
The script writes the system `TCC.db` directly and restarts `tccd`, which needs
SIP disabled in the guest; the owner disabled it in Recovery on 26 October 2026.
This is a lab-only deviation: the `clean` snapshot predates it, `approved`
includes it, and nothing in the product relies on it.

First registration and approval ran on 26 October 2026 this way: onboarding
Register, Login Items approval without an admin prompt, `launchctl print
system/com.magrathean.WGEXApp.dev.daemon` running, then `just lab snapshot
approved` (78 s). SMAppService reports `notFound` before the first register and
`register()` throws while approval is pending; both are handled in the app.

### Self-driven console (M03-T07, DEC-034)

The console login and the macOS administrator dialog cannot be reached from an
SSH session, so the rows that need them (M5.3-07, M5.3-09, LOGIN-SILENT) type
through the guest's own display. With `WGEX_LAB_VNC_FILE=<absolute path>` set,
`lab_start` (`lib.sh`) starts the restored guest headless with
`--vnc-experimental --no-graphics` (Virtualization.framework's VNC server on
127.0.0.1, no Tart window, DEC-112) and `CI=1`, so Tart writes its
`vnc://` address and one-time password into that file instead of opening the
host's Screen Sharing app. `lab_private_output` (`lib.sh`) opens the file and
checks the open descriptor before Tart writes to it: a regular file with one
link, owned by the user and still the file the path names, then set to 0600
and emptied; a link, a directory, a FIFO or a hard-linked file is refused. `Tools/lab/console/console.py` (standard library
only: `rfb.py` speaks RFB with VNC authentication) reads the file, reads the
lab password from `$WGEX_LAB_VM_ROOT/lab-login` at the moment of use and
types it into the login window (`login`) or SecurityAgent's dialog (`approve`),
never after `--deadline`: connect, authentication and every receive wait at
most until then, and the deadline is checked again right before the password;
`shot OUT.png` captures the framebuffer. The verdict driver runs it at its
`WGEX-G` moments: `login` 30 s after the logout, `approve` once
`gap-actions.sh agent-state` reads `agent=running windows=1`. The password is
never on a command line, in a log or in a capture (the fields show dots), and
only letters, digits and keys that match on the US and British layouts are
typed. Without the variable the guest still starts headless and Tart's VNC
output is discarded.

## Guest captures and Linux peer

Capture commands are always sent to the guest:

```sh
guest_user=labuser
just lab ssh -- bash "/Users/$guest_user/lab/capture/start-capture.sh" en0 baseline
# Substitute the actual guest WireGuard interface, such as utun4:
just lab ssh -- bash "/Users/$guest_user/lab/capture/start-capture.sh" utun4 tunnel
just lab pcaps
```

Helpers accept only `en0` or an explicit `utunN`, with a simple filename label.
They run guest tcpdump with `-w`; pcaps stay below the guest home in `lab/pcap`.
Root-owned PID records scope stop signals to recorded tcpdump processes.
`lab pcaps` stops and flushes guest captures, then uses scp into
`$(build_root)/lab-captures/manual`. Build output must be outside this repository;
symlink destinations are rejected. Fetch before a suite resets the guest, or
use `test smoke --keep`. The host never captures traffic.

`Tools/lab/lima/wg-peer.yaml` describes a separate 2 CPU, 2 GiB RAM, 12 GiB Linux
peer with kernel WireGuard and iperf3. It references a local Debian 13 ARM64
cloud image; the path is a preparation placeholder. No image exists or has
been inspected for this ticket, so no download-size claim is made. Before
creating it, report the chosen image's actual size and guest package download
requirements to the owner and obtain approval. Supply the image at the stated
path or edit the definition to an approved local path. Creation must use the
lab's `vm-lima` wrapper and its external store, with host mounts disabled.
Its guest-only provision block installs WireGuard tools and iperf3 and probes
the kernel driver. Access goes through `./vm-lima shell wg-peer` (Lima's own
instance key); the Mac public key is not authorised inside the peer.

`wg-peer` was created on 26 October 2026 from the Debian 13.x genericcloud
arm64 image (336 MB, SHA-512 verified against the published sums, stored at
`Lima/media/wg-peer-debian13-arm64.qcow2`). Two things to know:

- The image's default `https://deb.debian.org` apt mirror did not answer from
  the guest, so the first-boot provision block hung on `apt-get update`; the
  sources were switched to `http://mirrors.tuna.tsinghua.edu.cn` by hand and
  the packages installed afterwards. Recreating the peer needs the same step
  unless the definition grows a mirror override.
- Tart and Lima guests share the vmnet `192.168.64.0/24` bridge, but its
  members are isolated (bridge100 ports carry the PRIVATE flag): both guests
  reach the host, neither reaches the other. The lab therefore relays
  WireGuard UDP through the host with `host/udp-relay.py` (standard library,
  listens only on the host's vmnet address, no routes or pf changes):

  ```sh
  python3 -I Tools/lab/tart/host/udp-relay.py 192.168.64.1:51820 192.168.64.12:51820
  ```

  The guest profile's endpoint is then `192.168.64.1:51820`. The peer's `wg0`
  (`10.77.0.1/24`, listen 51820) and the throwaway client key pair live only
  inside the peer (`/etc/wireguard`); the client profile is copied into the
  Mac guest as `~/lab/wgex-lab.conf` with `10.77.0.0/24` as its only route so
  the host's SSH path to the guest is never captured. Lab keys only; never
  reuse them. Peer routing and throughput remain untested.

## macOS 27 guest

`macos27-wgex` (M03-T11) is a clone of the cached Cirrus image
`ghcr.io/cirruslabs/macos-golden-gate-base`, pinned by the sha256 digest that
DEC-019 records (`14f4fc32a778...`), with 4 CPUs and 8192 MiB; the earlier
guest of that name is kept as
`macos27-wgex-prev`. The same scripts drive it with three parameters, whose
defaults are the macOS 26 values:

```sh
export WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin WGEX_LAB_SNAPSHOT_PREFIX=macos27-
just lab restore base      # macos27-base -> macos27-wgex
just lab ssh -- sw_vers
```

`WGEX_LAB_USER` (default `labuser`) is the SSH and console user, also read by
`verdict-live.py`. `WGEX_LAB_SNAPSHOT_PREFIX` (default `$WGEX_LAB_VM-`) must
start with the VM's family (`macos27-`) and end with `-`; a snapshot or restore
that would name the working VM itself is refused. A `macos27` VM must report
macOS 27.x; a `macos26` VM still accepts 27.x with the note.

The image's administrator is `admin` with passwordless sudo, Remote Login on
and automatic login. Bootstrap needs no password: the tart guest agent
(`vm-tart exec macos27-wgex ...`) installed the Mac key's public half in
`/Users/admin/.ssh/authorized_keys`, and the guest's ed25519 host key, read
from `/etc/ssh/ssh_host_ed25519_key.pub` through the agent, is the second line
of `$WGEX_LAB_VM_ROOT/wgex-known_hosts` for the host-only subnet (OpenSSH
accepts any matching line, so both guests verify). `just lab trust` writes
the running guest's line tagged `wgex-lab-guest=macos27` (or `macos26`) and
replaces only the line with that tag or that same key, so the other guest's
line stays. `provision.sh` is not run on this guest (its `tester` account needs
a password); the marker `{"user":"admin"}` was written over SSH with the same
owner and mode checks. The image already holds system TCC allow rows for
`/usr/libexec/sshd-keygen-wrapper` and `/usr/bin/osascript` (Accessibility,
PostEvent, ScreenCapture, AppleEvents to System Events, and Full Disk Access
for the wrapper), so `just lab gui` works over SSH without `seed-tcc`. The
image ships with SIP disabled; the owner enables it in Recovery before the
`macos27-base` snapshot, and `seed-tcc` refuses once SIP is on.

## Safety and offline verification

Only `$WGEX_LAB_VM_ROOT/vm-tart` may operate on Tart guests. No fallback
store exists. Default VM is `macos26-wgex`; `WGEX_LAB_VM` may select a variant
whose name starts `macos26-wgex-`, or `macos27-wgex` and its variants (see
"macOS 27 guest"). Other farm guests are rejected. Override the
Mac key path with `WGEX_LAB_KEY`; no password source is supported. SSH ignores
user configuration and agents and requires trusted host keys. Host networking,
privileged services, routes, DNS and packet filtering are never changed.
The host has 36 GiB RAM and 12 cores; keep to two or three running guests and
stop them afterwards.

The compiled guard additionally needs `WGEX_LAB_BUILD`. Runtime environment
variables cannot enable it. The marker's JSON may later carry hooks such as
`crashAt`; provisioning starts from `{}` and resets those hooks on reruns. A
guest whose lab user is not `labuser` has `{"user":"NAME"}` instead; the guest
scripts read the user from it (`guard.sh` `guest_lab_user`), and the product
ignores the key.
Do not edit the marker on the host. Guest bootstrap checks the VM and OS before
creating it; every other guest mutation requires the complete marker check.

Host scripts accept `--dry-run` as their first argument. They print planned
mutations, simulate guest reads and never contact the guest. Simulated reads
are not evidence of a real guest. Offline tests inject fake tools only with
`--dry-run` and a fixture marker; the real wrapper remains mandatory otherwise.

```sh
bash Tools/lab/tart/tests/run.sh
shellcheck Tools/lab/tart/*.sh Tools/lab/tart/{capture,guest,tests}/*.sh
shfmt -i 2 -ci -d Tools/lab/tart
```

`Tools/lint/run-selftests.sh` has no extension hook, so it was left untouched.
Owner integration note: add `bash Tools/lab/tart/tests/run.sh` as an extra suite
when wiring central self-tests. No dependency has been added.

## M1-10 runner updates

`just lab verdict ROW --dry-run` writes only beneath build_root()/lab-verdict-replay by default; source-tree replay output is refused. Live runs require the M1-09 sidebar identifiers. The full row catalogue and controls are in Tests/Reports/M1/M1-10/README.md.

The verdict driver restores ready, builds/installs the current Lab app, quits any old app process, performs guarded guest chown/signature verification and daemon kickstart, and reopens the app. `--no-install` skips build/install/refresh only when the orchestrator explicitly asserts that the restored snapshot already has the current secure Lab build. The verdict records that assertion and the individual install steps. `WGEX_LAB_SNAPSHOT` selects a named snapshot instead of ready; it does not imply current binaries.

After every restore or peer re-key, run `just lab profile default` (or dns/full4/dual/lockdown) and import it again. The driver always regenerates the config from the peer and imports it after restore/install. It opens `wgex.main.sidebarImport`, routes the private guest file with `open -a WGEX PATH`, and presses `wgex.importReview.importAndConnect`; blackhole rows use `importLabel` to save before connecting. A duplicate review selects Replace so an obsolete same-name profile is not reused. Sidebar selection reads the public guest profile document to resolve the exact name to one UUID; sidebar status text is never treated as a profile name. SwiftUI sidebar rows ignore clicks, AXPress and AXSelected (run 5, L14), so selection is by keyboard: the AX dump starts with an `AXWindow | name=<title>` line and the main window titles itself with the selected profile name. AppKit joins the navigation title and subtitle with an en dash, so the title reads either `wgex-lab-VARIANT` or `wgex-lab-VARIANT – <status sentence>` (run 6, L16); both forms select, any other title does not, and the ledger records `titleForm` (`exact` or `statusSuffix`). If the title already names the profile, nothing is pressed; otherwise `just lab gui keys WGEX 1 wgex.main.profiles up N fallback` (N = sidebar rows, ordered by on-screen position) reaches the first row and `down I fallback` reaches the UUID's row, then the title must name `wgex-lab-VARIANT` within 5 s or the row fails with `profileSelectionMismatch` before any Connect. Run 6 found no element carrying `wgex.main.profiles` in the AX tree (L17), so the trailing `fallback` lets `guest/arrow-keys.applescript` take the keyboard path from the window: it focuses the outline, table or list that holds a `wgex.main.tunnel.<UUID>` row (walking AXParent from the row), else the window's first outline, table or list, and presses the same keys. The helper prints `path=identifier` or `path=window`; the ledger records it as `selectionPath` (`none` when no key was needed) and a mismatch names it. Without `fallback`, a missing identifier still fails with error 3. AXRadioGroup/AXGroup/AXRadioButton are included in dumps for the duplicate Replace control.

`just lab peer up --adopt` explicitly adopts an existing dedicated WireGuard wg0 and re-keys it to fixture keys. Peer up also persists the same configuration (plus `Address`) to `/etc/wireguard/wg0.conf`, which `wg-quick@wg0` loads at every peer boot, written atomically with mode 0600; the owner's original file is kept once as `/etc/wireguard/wgex-lab/wg0.conf.pre-wgex-lab` (L10). Before the first connect, prepare compares a 12-hex SHA-256 prefix of the live wg0 public key with the fixture `server.pub` and fails the row with `peerKeyMismatch` (run `just lab peer up`) instead of waiting out the 60 s protected deadline; the key itself never leaves the peer. It refuses another interface type. Verify ownership before choosing adoption; the default still refuses an unowned wg0. Prepare checks ownership with an actionable message before scoped fault cleanup. Cleanup of an absent fault, stale marker or vanished interface is idempotent; unrelated qdiscs are retained.

`WGEX_LAB_SSH_DEADLINE` defaults to **600 seconds** (valid 1..900) for manual command SSH/scp, including long observation scripts; prefer process-filtered `/usr/bin/log stream` during the action for diagnostics (always the absolute path in the guest: `log` is a zsh builtin there, L19). Set `WGEX_LAB_SSH_DEADLINE=900` explicitly if needed. The pipeline overrides short SSH/GUI probes to 90 seconds and observations to 600; clock-hop defaults to 90. Interactive `just lab ssh` has no overall deadline. Keepalives and key-only authentication remain enabled.

Each ledger command includes bounded, credential-redacted stderr. Failed prepare or incomplete rows write README/verdict under build_root()/lab-verdict-failures, including when a source-tree report root was requested. Each failed attempt is kept as `verdict-<n>.json` (exclusive create, `attempt` field) and `verdict.json` is a copy of the latest (L13); only replays and fully accepted rows may keep one verdict; completed rows with failed expectations retain every attempt. Only completed live rows with evaluated windows can write the source evidence tree; dry runs remain under lab-verdict-replay. The foreign-listener regression binds its own ephemeral loopback UDP port and reads it with lsof; it never inspects the live relay state or its port.

`gui shot` accepts paths under build_root() or TMPDIR and stages its temporary file under the build root. The author did not take screenshots. `pcaps` tolerates a missing legacy stop-capture helper and fetches completed files. The verdict runner uses its staged helpers and its own capture directory.

Managed `just lab relay start` reports a foreign listener with lsof and refuses to replace it. The owner must verify the current PID before stopping a foreign process; historical PIDs are not instructions to signal it. Start is idempotent when the managed relay already runs. `just lab relay mtu on|off` controls the row-scoped 1252-byte UDP datagram filter.

The default client profile is IPv4-only split (10.77.0.0/24 AllowedIPs), matching the importable P1-11 setup. `just lab profile full4` generates IPv4 /1 routes; `dual` adds fd77::2/64 and IPv6 /1 routes. Every variant carries `DNS = 10.77.0.1` (L11: since M1-06 a DNS-less tunnel never reports protected), so `dns` remains a valid name with the same content as `default`; Lockdown/wrong-key use full4 routes. Select peer topology with `just lab peer up --variant default|full4|dual|dns|lockdown|wrong-key` (one variant, optionally --adopt). Profile generation re-stages the current provision script and guard; never edit them by hand on the peer. Peer up re-keys wg0, so regenerate and import the selected profile afterwards.

Full-tunnel catalogue rows explicitly use full4. Rows declared `dependencies.daemonD5DNSVerification` (daemon D5) until M1-16 merged the fix (e90bfff); M1-10c cleared the key, so live dispatch accepts the rows again, and guest run 6 confirms D5. The dependency mechanism stays available for future gates.

IPERF3 runs a pinned static client in the guest (L12): `just lab iperf3 fetch` downloads userdocs/iperf3-static 3.22 `iperf3-arm64-osx-15` (version, asset, URL and SHA-256 recorded in `Toolchain.lock`), verifies the digest before storing it at `~/.wgex-lab/tools/iperf3-static/3.22/iperf3`, shared across checkouts, and never places it in the repository; `just lab iperf3 path` prints it only when it verifies. Prepare re-verifies the host copy, stages it after every restore to `~/lab/bin/iperf3` (digest checked again in the guest) and the row runs it by absolute path. A missing or mismatched client fails the row with `iperf3Missing` before the peer's one-shot server starts. The peer already has Debian's iperf3.

Action diagnostics use a guest-only process-filtered log stream, armed before actions and filtered through a FIFO into a numeric count and a tail of at most 50 allowlisted diagnostic lines; raw messages are never persisted. A run of omitted events is one counted line (`<N events omitted; non-diagnostic content>`), so noise cannot push the L7 `status:`, `verifier:`, `pf:` and `ownership:` lines out of a deadline capture (L13). Since M1-10d (L20) the allowlist also keeps the Lab-only `ownership:` verdicts: the fixed event labels (for example `ownership: canary adopted`, `ownership: canary replaced`, `ownership: foreign route`, `ownership: tunnel descriptor missing`) and `ownership: interface <name> index <recorded>-><current> check index|descriptor|link address|address` or `...->absent`, each anchored at the end of the line; any other `ownership:` text is omitted. Observe returns only that count; teardown validates/stops its stage-owned PID. After reboot the stream resumes after SSH, leaving earlier boot events outside diagnostic coverage. Markers must be quoted printf strings for guest zsh, e.g. `printf '%s\n' '===STATUS'`; bare echo ===STATUS is a glob error.

Third live-run recovery: immediately after restore the verdict driver retries short SSH discovery with backoff for up to 120 s before staging. lib.sh also retries Tart ARP/DHCP address publication and SSH within WGEX_LAB_CONNECT_TIMEOUT (default 120 s, maximum 120; probes at most 5 s). The driver uses shorter budgets for short probes. App Quit activates WGEX and polls for the menu bar/item, then falls back through AppleEvent quit and guest-only pkill -x WGEX, requiring exit and recording the path.

Persistent non-secret state lives in ~/.local/state/wgex-lab/<tree-name>-<12-hex-path-digest>/, independent of build/scratch roots. Use `python3 -I -B Tools/lab/state.py path` to inspect the computed path. just test tools compiles under build_root() and publishes the two guest helper binaries plus manifest to stable helpers/; these copies survive a build-root change and are re-staged into the guest after restore. The relay PID/control/log live in stable relay/. pgrep/ps identifies this tree's exact relay command/endpoints even without a current PID file. A matching stable-control process is adopted; a matching old-control process is restarted using stable control. Stop revalidates ownership before signals. Unrelated listeners remain untouched and are reported with PID.

Status and aggregate observation stdout are redacted and capped at 64 KiB each in the ledger. Poll deadlines write named deadline-N.json records in the run's build output, including last status JSON, last 50 already allowlisted stream lines and the ledger tail. The stream filter reconstructs only known public diagnostic fields/messages and omits unknown payloads before writing. Reports/captures/caches remain under routed build/scratch roots; only the owner-requested helper/runtime state is retained in the stable directory.

## Ready snapshots and the manual app path (M1-10d)

A `ready` snapshot (`ready`, `ready6b`, `ready8` and so on) is taken only after
the app's first-run onboarding has completed. A snapshot taken before it boots
to the "Set up WGEX" window with no main window, so prepare cannot find
`wgex.main.sidebarImport` (guest run 6). On this build onboarding is seven
presses of `wgex.onboarding.continue` (welcome, background service, approve the
service, secure install, add your first profile, connection at startup,
automatic failover) and then "Open WGEX" on "Ready to connect":

```sh
guest_user=labuser
just lab restore approved
just lab gui run open -a WGEX
just lab gui activate WGEX
just lab gui dump WGEX 1     # find wgex.onboarding.continue; click the centre (pos + size/2)
just lab gui click X Y       # 7 x Continue, dumping after each; leave the profile, startup and failover steps untouched
just lab gui click X Y       # "Open WGEX"
just lab gui dump WGEX 1     # main window "WGEX – No tunnels" with wgex.main.sidebarImport
just lab ssh -- grep -c '"onboardingComplete":true' "/Users/$guest_user/Library/Application Support/WGEX/mac-preferences.json"
just lab snapshot ready9     # a new name; existing snapshots are never replaced
```

`snapshot.sh` prints this prerequisite for every `ready*` name. On the
`approved` lineage the secure-install step already reads "Secure install
verified", so no admin dialog appears and no authorization right is exercised.
The old authorizationdb pre-allow is therefore not needed, and it is not
accepted any more either: the app accepts the
`com.magrathean.WGEXApp.manage-protection.dev` right only as class rule
`authenticate-admin-nonshared` (admin, not shared, 30 s; M01-T02) and fails closed with
`adminRightRequired` on an `allow` rule, and the daemon rewrites the right at
startup. Do not write authorizationdb rows in the guest.

While the selector fixes (L16, L17) await guest confirmation, the manual app
path from guest run 6 (M1-18 evidence) is the fallback for a connect:

```sh
guest_user=labuser
just lab profile dns          # or default, full4, dual, lockdown
just lab gui activate WGEX
just lab gui run open -a WGEX "/Users/$guest_user/lab/wgex-lab-dns.conf"
just lab gui dump WGEX 1      # review sheet: wgex.importReview.importAndConnect ("Import and connect")
just lab gui click X Y        # its centre; the imported profile is selected and connects
just lab gui dump WGEX 1      # main window: wgex.main.action desc=Disconnect, or Connect/Reconnect when idle or failed
just lab gui click X Y        # Disconnect or Reconnect at the dumped centre
just lab ssh -- /Applications/WGEX.app/Contents/Helpers/wgex status --json
```

The guest file path is absolute because `gui run` passes arguments as data and
`~` is not expanded. In a failed state the toolbar offers only Reconnect and
More; use `just lab ssh -- /Applications/WGEX.app/Contents/Helpers/wgex down`
to disconnect. Read daemon diagnostics in the guest with the absolute
`/usr/bin/log` (the guest login shell is zsh, where `log` is a builtin), for
example `/usr/bin/log show --last 5m --style compact --predicate 'process ==
"WGEXDaemon"'`, and keep its output in the guest or a scratch directory, never
in a report.

## ready11: reinstalls keep the wrapping key (M01-T04)

Lab builds stay ad hoc signed (`Config/Signing-AdHoc.xcconfig`), so every rebuild
changes the daemon's cdhash, and the System-keychain wrapping key's decrypt ACL
pins the cdhash of the daemon that was installed when the key was written. Run 9b
F1 showed the result: after `just lab install` the new daemon was refused the key
(`CSSMERR_CSP_OPERATION_AUTH_DENIED`, Secure Install
`needsAttention(wrappingKeyUnavailable)`, failed/backendUnavailable) until an
administrator approved Secure Install. A stable certificate signature is not
available to the lab: the signing settings are product inputs that a verdict
requires unchanged from main, and the Lab daemon itself only writes a cdhash ACL.

`guest/wrapping-key.sh` (run by `just lab install` after every install) therefore
keeps the lab's own key in a root-only escrow inside the guest
(`/var/db/wgex-lab-keys/<service>.key`, 0600, plus the item's creation date) and,
when the installed daemon's cdhash differs from the one the ACL trusts, deletes
the item and re-adds the same bytes trusting only the new daemon. Stored secrets
stay readable, the ACL keeps the single-daemon cdhash shape the daemon writes, the
key never appears in argv, output or the host, and no prompt is raised. A key the
lab did not create (no escrow, or another creation date) is left alone and the
install reports it. The install line names the outcome (`re-trusted`,
`unchanged`, `restored from the lab escrow`, `provisioned and escrowed`), and the
verdict driver records it as `installation.wrappingKey`; after `refresh-install`
it reads `wgex doctor --json` and fails prepare with `wrappingKeyUnreadable`
unless Secure Install is `verified` (`installation.secureInstall`).

The daemon's approval survives a reinstall with no click (the launchd job keeps
running the new binary after `refresh-install`). No authorizationdb row is
written: since M01-T02 the daemon refuses a pre-allowed (`allow`) right, and no
admin-right path runs on an install.

ready11 was made once from ready10 (onboarding done, no profiles, an unescrowed
key and no ciphertext). ready10 no longer exists (DEC-039), so ready11 is the base
for every macOS 26 run and is never replaced. Should a successor ever be needed,
rebuild it from `approved` under a new name: run the onboarding of the manual app
path above first, then

```sh
guest_user=labuser
# Stage guest/wrapping-key.sh and guest/guard.sh under ~/lab/keystage, then:
just lab ssh -- bash "/Users/$guest_user/lab/keystage/wrapping-key.sh" --replace-unescrowed com.magrathean.WGEXApp.dev.daemon
just lab build && just lab install     # re-trusts the escrowed key for the new daemon
just lab ssh -- sudo -n chown -R root:wheel /Applications/WGEX.app   # then kickstart, as refresh-install does
just lab snapshot ready12              # a new name; existing snapshots are never replaced
```

## macos27-ready: the macOS 27 rows' snapshot (M03-T10)

`Tools/lab/ready-snapshot.py` makes `macos27-ready` from `macos27-base` in one run,
the macOS 27 counterpart of ready11:

```sh
export WGEX_LAB_VM=macos27-wgex WGEX_LAB_USER=admin WGEX_LAB_SNAPSHOT_PREFIX=macos27-
export WGEX_LAB_GUEST_PASSWORD_FILE="$TMPDIR/guest-pw"   # 0600, the image's public default; removed when read
python3 -I -B Tools/lab/ready-snapshot.py --out "$(python3 -I -B Tools/lab/state.py path)"   # any directory outside the tree
```

It restores `macos27-base`, builds and installs the Lab app with the wrapping-key
escrow ("provisioned and escrowed": DEC-007's stable lab signing; no authorizationdb
row is written and no password is typed into a WGEX sheet), makes the bundle
root-owned, opens the app, presses Continue twice and Register, and approves the
background item in System Settings. macOS 27 asks for an administrator there; the
driver fills that Login Items sheet only (AUTH-REAL's fill, DEC-034). With the
daemon running and Secure Install already `verified` (the escrowed key is
readable, so no WGEX sheet), it presses Continue until the app records
`onboardingComplete`, checks that the daemon wrote its own right, quits the app and
runs `just lab snapshot ready`. Existing names are never replaced; the run stops
without a snapshot when any check fails. Every run, taken or not, ends with
`just lab down` (the snapshot restarts the guest); a failed stop is recorded in
`ready-snapshot.json` and fails the run. The rows then run with
`WGEX_LAB_SNAPSHOT=ready` and the three macOS 27 parameters, for example
`just lab verdict M5.1-01 --report-root Tests/Reports/v2/macos27` after
`just lab peer up --variant full4`.

`--replace-unescrowed` deletes an unescrowed key only while no `.blob` exists
under the daemon's secrets directory, then provisions an escrowed one. Snapshots
from ready11 on carry the escrow. Never install a build whose bundle version is
lower than one the guest has run: the daemon's floor refuses it
(`downgradeDetected`); restore the snapshot instead.

## ONDEMAND-ETH: the on-demand Ethernet row (M03-T09)

`just lab peer up --variant full4`, then `WGEX_LAB_SNAPSHOT=ready11 just lab verdict ONDEMAND-ETH --report-root Tests/Reports/v2`
(allow 4200 s). The row imports `full4` without connecting and runs the unprotected lead control before Lockdown, which it turns on
and never off (ADR-030 is evaluated by the daemon; the Tart guest has Ethernet and no Wi-Fi, so only the Ethernet rule is measured).
Everything is driven through the product, with no password and no host change:

1. Editor: `wgex.main.editProfile`, tick `wgex.editor.onDemandEthernet`, `wgex.editor.save`; `gap-actions.sh od-policy` reads the saved
   policy back from the app's profile store (`profile.onDemand`: `off` before, `ethernetOnly` after).
2. Arm: one press of `wgex.main.onDemandToggle.<profile UUID>`; the tunnel comes up with no other action.
3. Daemon start: `gap-actions.sh od-restart` sends SIGTERM to the Lab daemon; `od-probe` samples the replacement daemon (pid, status and
   on-demand fields, reduced by `guest/od-status.pl`, never an SSID). Each read is bracketed by two reads of the daemon's pid and start
   time and is kept only when both are available and identical; otherwise it is discarded and its reason (`daemonChanged`,
   `identityUnavailable`) is recorded. Only kept samples whose pid and start time both differ from the old daemon's count.
4. en0 returns: the existing guarded `en0-loss` action cycles en0 inside the guest (20 s down, then up), judged by EN0-LOSS's own checks.
5. Removal: Lockdown on, a second press of the toggle (disarm and deactivate) takes the tunnel down (idle, blocked); a second en0 cycle
   must leave it down. While the link is down the daemon may report protection `unknown` for a moment; the check allows that only
   from en0 down to 10 s after it is up.

Saving the rule as off while the tunnel runs leaves the tunnel up by design (ADR-030 section 6 rule 7), so it is not the removal step.

## UNINSTALL: the uninstall row (M03-T15)

`just lab peer up --variant full4`, then `env WGEX_LAB_VNC_FILE="$TMPDIR/vnc-UNINSTALL.txt" WGEX_LAB_SNAPSHOT=ready11 just lab verdict
UNINSTALL --report-root Tests/Reports/v2` (allow 4200 s; four administrator approvals, typed at the guest console by
`console/console.py` as DEC-034 allows). The row imports `full4` without connecting, so its first observation is the pre-tunnel
baseline (inet routes and the resolver sets, default and scoped). It turns on Connect at login (the app's own login item), then runs two variants, keep
(`wgex uninstall --yes`) and purge (`wgex uninstall --purge --yes`), each the same way:

1. Connect `full4` and probe protected; read pf (`com.apple/wgex` rules, tables, nested anchors, references), routes, resolvers,
   the launchd job and the BTM items (`uninstall/guest-uninstall.sh pf` and `services`); before the purge, also the state root
   (its generation while protected); quit the app.
2. `guest-uninstall.sh cli-start` runs the product CLI as the console user in the console session (`launchctl asuser`), so its
   administrator dialog appears at the guest console; the driver types it once SecurityAgent shows its window.
3. Read what the uninstall left: status (`wgex status --json` reduced, and the text form's `uninstall:` line), pf, routes, resolvers, launchd and BTM, the console user's
   `up` and `on-demand on` requests (each must be refused with `uninstallFailed`), the app's profile store and, after a purge, the
   daemon state root (file names, and the replayed journal reduced in the pipe to each field's exact type, the generation number
   and fixed booleans for the default settings, the disconnected pf policy and the completed purge marker). Probe unprotected.
4. Open the app: it offers to finish the CLI's uninstall; Finish (`wgex.service.uninstallConfirm`) must remove the launchd job and
   the login item and reach the final screen within 90 s (the ServiceController.unregister hang watch); its Quit
   (`wgex.service.uninstallQuit`) must end the app. A Quit that leaves the app running is recorded, then `stop-app` ends it and
   finalQuitEndsApp is unmet.
5. Fresh secure install from the app: Settings, Service, `wgex.onboarding.registerBackgroundService`, then the secure install
   action (`wgex.service.actionTitle`, administrator dialog at the guest console); connect `full4` and probe protected. A tunnel that
   does not start within 90 s is recorded with the daemon's start-failure line; the driver then restarts the daemon once
   (`restart-daemon`, recorded) so the next variant can run, and the check stays unmet.

statusReportsUninstalled matches the M05-T14 output: the JSON's top-level `uninstall` is `{"completed": true, "purgeState": <purge
variant>, "pendingStep": null}`, and the text has a line starting `uninstall: completed; the service is uninstalled;` (keep) or
`uninstall: completed (purge); the service is uninstalled;` (purge).

pf keeps an emptied anchor's name listed under `com.apple` once the daemon has loaded it (the baseline lists it too), so the row
requires the anchor empty with no pf reference, and records whether it is listed. The final unprotected tail runs after the purge
variant's fresh install.

dnsAsBeforeTunnel compares both scutil sections, so a tunnel resolver left only in the scoped section fails. stateRootMarkerOnly
requires exactly the fields of the fresh document the purge writes (TunnelController+Uninstall), each of its exact type, and a
generation no lower than the one read while protected. A guest read that fails (launchctl other than 113, pgrep other than 1,
sfltool, pfctl, the state root's sudo or find) is `unknown`, and a failed journal replay is `unreadable`; neither is ever an
absence or a zero, so the check that reads it fails.
