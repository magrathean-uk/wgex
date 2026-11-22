# ADR-028 Document types and ZIP import

Status: Accepted 2026-10-25

**Decision.** WGEX registers UTType `com.wireguard.config` (`.conf`) as a viewer on macOS, iOS and iPadOS, so Finder double-click, Files, Mail and AirDrop Open-In route into the review screen. ZIP import uses a bounded reader: at most 1,024 entries including ignored files and directories, 256 KiB per configuration entry, and 256 MiB each for compressed input and total advertised expanded data (`Packages/WGEXProfileStore/Sources/WGEXProfileStore/ZipArchiveReader.swift:10`, `Packages/WGEXCore/Sources/WGEXCore/Configuration/ConfigDiagnostic.swift:33`). Stored and deflate entries are supported (`Packages/WGEXProfileStore/Sources/WGEXProfileStore/ZipArchiveReader.swift:18`).

On Mac, Export All Tunnels is available in the main window and File menu; it warns about keys before opening a save panel and writes flat `.conf` entries in a ZIP (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift:296`, `Apps/WGEXMac/WGEXMacApp.swift:37`, `Apps/WGEXMac/WGEXMacApp.swift:268`, `Apps/WGEXMac/MacAppModel+ExportAll.swift:12`, `Apps/WGEXMac/MacTunnelArchive.swift:9`, `Packages/WGEXUI/Sources/WGEXUI/Presentation/MacStrings+Export.swift:29`). The menu-bar Import Tunnels command opens the main window's importer (`Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift:112`, `Apps/WGEXMac/WGEXMacApp.swift:183`, `Apps/WGEXMac/MacAppModel+Import.swift:17`).

