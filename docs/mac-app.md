# WGEX on the Mac

A guide to the Mac app's screens. WGEX keeps to the system look: a standard text menu, one window in the System Settings style, and the system font and controls. State is said in words, never in coloured dots or badges.

## Words

- A WireGuard configuration the app manages is a **tunnel**.
- A tunnel is **Active** or **Inactive**. You **Activate** and **Deactivate** it. While it starts or restarts the status reads **Activating…** or **Reconnecting…**.
- **Kill switch** blocks all traffic if the tunnel drops. **Lockdown** keeps blocking after a restart until a tunnel is up.
- The **Sign-in window** pauses protection for a short time so you can reach a Wi-Fi sign-in page.
- The **Background service** keeps the tunnel running after you close the window.
- A value the app cannot read says **Unavailable**; it is never shown as zero.

Buttons and menu items use title case. Row labels use sentence case. An ellipsis marks anything that opens a sheet or a window.

## Menu

The menu bar holds a plain text menu with no icons, switches or buttons:

- A **Status** line (Active, Inactive, Activating…, Reconnecting…, Traffic blocked, Unprotected for m:ss or Unknown).
- Your tunnels, in the same order as the window's sidebar. The active tunnel is ticked; choosing an unticked tunnel activates it and choosing the ticked one deactivates it.
- While a tunnel is active, detail lines under it: interface, address, DNS, endpoint, MTU, last handshake, download and upload rates with totals, and the kill switch state. A line with no value for this tunnel is left out.
- **Manage Tunnels…**, **Import Tunnels from File…**, **About WGEX** and **Quit WGEX**.

When traffic is blocked the menu offers **Sign In to This Network…**; while the Sign-in window is open it offers **End Sign-In Now**. When the Background service is not answering it offers **Open WGEX…**.

## Window

One window with a sidebar. Under **Tunnels** are your tunnels, each with a short grey status word when it is not inactive, and **Add Tunnel…** at the foot. Under **Settings** are the app pages: General, Protection, Background Service, Log and About. The window opens on the active tunnel, else the default tunnel, else the first tunnel. With no tunnels it shows an empty page with **Import from File…** and **Paste from Clipboard**, and you can drop a `.conf` file on it.

### Tunnel page

The page is titled with the tunnel's name and starts with its status and an **Activate** or **Deactivate** button. Groups follow in a fixed order:

- **Traffic** (only while the tunnel is up): download, upload and last handshake.
- **Addresses**: tunnel address, IPv6 address, DNS and routes.
- **Server**: name, address, public key and keepalive. A tunnel with several servers shows **Server 1**, **Server 2** and so on.
- **Protection**: kill switch and local network (these lead to the Protection page), plus Connect on demand and Connect automatically, which belong to this tunnel and open as a sheet.
- **Advanced**: interface, MTU and this Mac's public key.

**Edit…**, **Export…** and **Delete Tunnel…** sit at the foot. Every value can be selected and copied; keys are shortened on screen and copied in full. The private key is never shown here.

When traffic is blocked the page offers the Sign-in window with a short explanation; while the window is open it offers **End Sign-In Now**. When the Background service is not answering the page offers **Open Background Service**.

### Add, Review and Edit sheets

- **Add a Tunnel** offers **Import from File…**, **Paste from Clipboard** and **Create Empty Tunnel**. Use a WireGuard configuration made for this Mac.
- **Review Tunnel** appears after any import and before anything is saved. It shows the name (which you can change), server, tunnel address and routes, and lists problems in plain words, such as commands that are not supported and were removed. Choose **Cancel**, **Add** or **Add and Activate**.
- **Edit** shows the same grouped form: name, private key (shown as dots until you click it), addresses and DNS, then each server. **Add Server** adds one. **Edit as Text** swaps the form for the raw configuration, and both views edit the same tunnel.
- **Delete Tunnel…** asks for confirmation. Deleting the active tunnel deactivates it first and says so.

## First-run setup

Three sheets on the main window, with three progress dots:

1. **Welcome to WGEX**: what the app is and is not (no accounts, no provided servers, no analytics).
2. **Allow WGEX in the Background**: macOS asks once to allow the Background service. Continue stays disabled until the service is running.
3. **Add a Tunnel**: the sheet above, or **Not Now** to leave with the empty window.

Anything else you might change later lives on an app page.

## App pages

- **General**: default tunnel, Connect automatically (Never, When I log in, At start-up), show WGEX in the Dock and a notifications switch. The notifications switch is kept with a note that it arrives in a later update.
- **Protection**: the kill switch state, Lockdown, Allow local network and the Sign-in window length, then what WGEX cannot protect: traffic during a Sign-in window, local traffic when local network is allowed, traffic to a tunnel's [exclusions](protection-semantics.md#tunnel-exclusions), and the time before the disk is unlocked at start-up. The full list of known gaps is in [protection-semantics.md](protection-semantics.md).
- **Background Service**: whether it is running, whether macOS has allowed it, and whether the copy in Applications is verified. **Open Login Items Settings…** and **Register Again** are here. **Uninstall WGEX…** sits alone at the foot and lets you choose whether to keep your tunnels.
- **Log**: Events (time, category, plain sentence) and a Raw log, with **Save Log…** and **Export Diagnostics…**. Newest entries are at the bottom. Diagnostics exports never include private keys.
- **About**: version and build, the MIT licence, thanks to the WireGuard project, acknowledgements and the WireGuard trademark notice.
