# SPDX-License-Identifier: MIT
"""Hash engine inputs and reject missing, stale or incomplete binary archives."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SLICES = {"macos", "ios", "tvos", "ios-simulator", "tvos-simulator"}
ARTEFACTS = ("provenance.json", "provenance-test.json", "WGEXEngine.xcframework", "WGEXEngineTest.xcframework")
OWN_BINARY = "Packages/WGEXEngine/Binary"


class SourceDiscoveryError(ValueError):
    """Git could not enumerate engine inputs; rebuilding cannot repair discovery."""


class ArtefactLinkError(ValueError):
    """An engine artefact, or the Binary directory or a parent, is a link, so it may be another tree's build."""


def refuse_links(root, binary, test_support=False):
    """M1-28: one tree's engine build must never verify, or be overwritten through, another tree's artefacts.

    One root-anchored rule: a path that names, or resolves to, a Packages/WGEXEngine/Binary must resolve to exactly
    <resolved root>/Packages/WGEXEngine/Binary, so a link on Binary, on Packages/WGEXEngine or on Packages, a path
    that reaches the tree through an alias, and a '..' path into another tree are all refused. "Names or resolves to"
    and the comparison are case-insensitive (M1-35): the volume may ignore case, so 'packages/wgexengine/binary' is the
    same directory, and a link elsewhere that resolves to another tree's Binary is judged by where it resolves. Writers
    and doctor apply the same comparison (Engine/scripts/lib.sh require_own_binary, Tools/doctor/doctor.sh).
    """
    recipe = "just engine-test" if test_support else "just engine"

    def refuse(name, path, reason):
        target = os.readlink(path) if path.is_symlink() else str(path.resolve())
        raise ArtefactLinkError(f"symlinked engine artefact {name} ({reason}: {target}); "
                                f"remove the link and run '{recipe}' before building")
    shape = tuple(part.casefold() for part in OWN_BINARY.split("/"))
    named = Path(os.path.abspath(binary))
    resolved = binary.resolve()
    expected = root.resolve() / OWN_BINARY
    own_style = any(tuple(part.casefold() for part in path.parts[-3:]) == shape for path in (named, resolved))
    if (own_style and str(resolved).casefold() != str(expected).casefold()) or binary.is_symlink():
        refuse(OWN_BINARY, binary, "Packages/WGEXEngine/Binary or a parent is a link or resolves outside this tree")
    for name in ARTEFACTS:
        path = binary / name
        if path.is_symlink():
            refuse(name, path, "a link")


def app_version_values(root):
    config = root / "Config/Base.xcconfig"
    text = config.read_text() if config.is_file() else ""
    values = []
    for override, setting, fallback in (("WGEX_APP_VERSION", "MARKETING_VERSION", "0.0.0"),
                                        ("WGEX_BUILD", "CURRENT_PROJECT_VERSION", "0")):
        match = re.search(rf"^[ \t]*{setting}[ \t]*=[ \t]*([^\s]+)", text, re.MULTILINE)
        value = os.environ.get(override) or (match.group(1) if match else fallback)
        if not re.fullmatch(r"[A-Za-z0-9._+\-]+", value):
            raise ValueError("app version/build may only contain [A-Za-z0-9._+-]")
        values.append(value)
    return values


def source_digest(root):
    try:
        inputs = subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
             "Engine/go", "Engine/scripts"], stderr=subprocess.PIPE).decode().split("\0")
    except subprocess.CalledProcessError as error:
        raise SourceDiscoveryError("source discovery failed: git ls-files could not enumerate engine inputs; use a readable Git checkout") from error
    names = {name for name in inputs if name and (
        name.startswith("Engine/scripts/") or
        name.startswith("Engine/go/") and (not name.startswith("Engine/go/vendor/") or
                                           name == "Engine/go/vendor/modules.txt"))}
    digest = hashlib.sha256()
    def add(name, data):
        digest.update(name.encode() + b"\0")
        digest.update(str(len(data)).encode() + b"\0" + data)
    for name in sorted(names):
        path = root / name
        if path.is_file():
            add(name, path.read_bytes())
    # Toolchain.lock floors are host eligibility policy, not compilation inputs: editing a floor cannot change these
    # sources, and assert_toolchain still enforces it. The tools that compile are keyed separately (toolchain_key),
    # so a toolchain change rebuilds once and a floor edit never does.
    for name, value in zip(("APP_VERSION", "APP_BUILD"), app_version_values(root), strict=True):
        add("build-info:" + name, value.encode())
    return digest.hexdigest()


def toolchain_key(go_version, xcode_version, xcode_build):
    """M1-46: the compiling toolchain as an engine cache-key component.

    Hashes the found `go version` output and the Xcode version and build, never the Toolchain.lock floors, so a
    floor edit does not rebuild and a toolchain change rebuilds once. Kept apart from source_digest(), which the
    archive embeds and Config/Scripts/lib.sh verifies from build phases that may not have Go on PATH.
    """
    text = "\0".join(("go:" + go_version.strip(), "xcode:" + xcode_version.strip(), "build:" + xcode_build.strip()))
    return hashlib.sha256(text.encode()).hexdigest()


def provenance_tools(binary):
    """The Go and Xcode versions recorded in the production provenance, i.e. the tools that built the archive."""
    data = json.loads((binary / "provenance.json").read_text())
    return f"{data['go']}, Xcode {data['xcode']}"


def verify(root, binary, test_support, toolchain=None):
    refuse_links(root, binary, test_support)
    provenance = binary / ("provenance-test.json" if test_support else "provenance.json")
    data = json.loads(provenance.read_text())
    digest = source_digest(root)
    if data["source_sha256"] != digest:
        raise ValueError("engine source digest differs")
    if toolchain is not None and data["toolchain_sha256"] != toolchain_key(*toolchain):
        raise ValueError("engine toolchain differs")
    expected = {"macos"} if test_support else SLICES
    if set(data["slices"]) != expected:
        raise ValueError("engine slice manifest is incomplete")
    xcf = binary / ("WGEXEngineTest.xcframework" if test_support else "WGEXEngine.xcframework")
    info = plistlib.loads((xcf / "Info.plist").read_bytes())
    libraries = info["AvailableLibraries"]
    if len(libraries) != len(expected):
        raise ValueError("XCFramework has the wrong slice count")
    seen = set()
    for library in libraries:
        platform = library["SupportedPlatform"]
        key = platform + ("-simulator" if library.get("SupportedPlatformVariant") == "simulator" else "")
        if key in seen or key not in expected or library["SupportedArchitectures"] != ["arm64"]:
            raise ValueError("unexpected XCFramework slice")
        seen.add(key)
        archive = xcf / library["LibraryIdentifier"] / library["LibraryPath"]
        if archive.is_symlink() or not archive.resolve().is_relative_to(xcf.resolve()):
            raise ArtefactLinkError(f"symlinked engine artefact {xcf.name}/{library['LibraryIdentifier']} "
                                    "(the archive is a link or resolves outside the XCFramework); "
                                    f"remove the link and run '{'just engine-test' if test_support else 'just engine'}' "
                                    "before building")
        if hashlib.sha256(archive.read_bytes()).hexdigest() != data["slices"][key]["libwgex_sha256"]:
            raise ValueError("XCFramework archive checksum differs")
        if digest.encode() not in archive.read_bytes():
            raise ValueError("XCFramework build info lacks the source digest")
    if seen != expected:
        raise ValueError("XCFramework slice coverage differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--test-support", action="store_true")
    parser.add_argument("--app-version-values", action="store_true")
    parser.add_argument("--toolchain", nargs=3, metavar=("GO_VERSION_OUTPUT", "XCODE_VERSION", "XCODE_BUILD"),
                        help="found toolchain: with --verify it must match the archive's, alone it prints its key")
    parser.add_argument("--provenance-tools", type=Path, metavar="BINARY_DIR",
                        help="print the Go and Xcode versions recorded in BINARY_DIR/provenance.json")
    args = parser.parse_args()
    try:
        if args.app_version_values:
            print("\n".join(app_version_values(args.root)))
        elif args.provenance_tools:
            print(provenance_tools(args.provenance_tools))
        elif args.verify:
            verify(args.root, args.verify, args.test_support, args.toolchain)
        elif args.toolchain:
            print(toolchain_key(*args.toolchain))
        else:
            print(source_digest(args.root))
    except (SourceDiscoveryError, ArtefactLinkError) as error:
        sys.stderr.write(f"engine: {error}\n")
        return 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        recipe = "engine-test" if args.test_support else "engine"
        sys.stderr.write(f"engine: missing or stale XCFramework ({error}); run 'just {recipe}' before building\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
