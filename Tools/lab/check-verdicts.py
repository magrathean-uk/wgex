#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed lab acceptance reader and shared build provenance helpers.

Build receipts are written before and after the Lab build, outside the checkout.
The fourteen rehearsal keys below are the producer contract for M03-T08.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
# One list for both the producer's working-tree check and the reader's bounds.
# Config and Engine include their complete build/signing script chains.
PRODUCT_PATHS = ("Apps", "Daemon", "Packages", "Engine", "Config", "Vendor",
                 "project.yml", "Toolchain.lock", "justfile", "Tools/lab/tart/build.sh",
                 "Tools/lab/tart/lab.sh", "Tools/lab/tart/lib.sh", "Tools/lab/tart/install-app.sh",
                 "Tools/lab/check-verdicts.py")
BINARIES = {"app": "Contents/MacOS/WGEX", "daemon": "Contents/MacOS/WGEXDaemon",
            "cli": "Contents/Helpers/wgex"}
BUILD_TARGETS = ("WGEXMac", "WGEXDaemon", "WGEXCLI")
REHEARSAL_CHECKS = (
    "expiryRollback", "confirmThenRebootRestoresIntent", "abort", "rebootWhileArmedRollback",
    "receiverLeakVerdict", "unrelatedRoutesAndReferencesPreserved", "dedicatedPeerHandshake",
    "appAbsentAndPresent", "failedStopRetry", "restartDuringRollback", "confirmedRestartRestoresIntent",
    "rebootWindowUnprotectedRecoveryNotBlocked", "manualRecoveryDevDaemon", "oldGuestClientAvailable",
)
COMMIT = re.compile(r"[0-9a-f]{40}")
CDHASH = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
CONDITIONS = "$(inherited) DEBUG WGEX_LAB_BUILD"
# M03-T03: the one row that installs a different bundle on purpose. Its end-of-row re-measure is replaced by the
# update bundle's own receipt and installed hashes (update_errors); verdict-live.UPDATE_ROW mirrors it (a test keeps them equal).
UPDATE_ROW = "M5.3-07"


def command(argv, root=ROOT):
    result = subprocess.run(argv, cwd=root, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    if result.returncode:
        # Tool output can contain credentials. Never echo it into acceptance output.
        raise ValueError("command failed: " + argv[0])
    return result.stdout.decode()


def git(*args, root=ROOT):
    return command(["git", *args], root).strip()


def ancestor(older, newer, root=ROOT):
    return git("merge-base", older, newer, root=root) == older


def product_changes(source, target=None, root=ROOT):
    # No target means tracked staged AND unstaged changes against source.
    changed = git("diff", "--name-only", source, *([target] if target else []), "--", *PRODUCT_PATHS, root=root)
    if target is None:
        untracked = git("ls-files", "--others", "--exclude-standard", "--", *PRODUCT_PATHS, root=root)
        changed = "\n".join(filter(None, (changed, untracked)))
    return changed


def source_commit(root=ROOT):
    source = git("merge-base", "HEAD", "main", root=root)
    if not COMMIT.fullmatch(source) or product_changes(source, root=root):
        raise ValueError("sourceCommit: product paths differ from merge-base with main")
    return source


def build_arguments(bundle_version=None):
    # Query all three explicitly: scheme showBuildSettings need not include its
    # implicit dependencies, even though the scheme builds them.
    args = ["-project", "WGEX.xcodeproj", "-configuration", "Lab",
            "-disableAutomaticPackageResolution",
            "-onlyUsePackageVersionsFromResolvedFile", "-skipPackageUpdates",
            "SWIFT_ACTIVE_COMPILATION_CONDITIONS=" + CONDITIONS, "WGEX_LAB_BUILD=1"]
    for target in BUILD_TARGETS:
        args.extend(("-target", target))
    version = os.environ.get("WGEX_LAB_BUNDLE_VERSION", "") if bundle_version is None else bundle_version
    if version:
        if not re.fullmatch(r"[1-9][0-9]*", version):
            raise ValueError("buildInputs: invalid bundle-version override")
        args.append("CURRENT_PROJECT_VERSION=" + version)
    return args


def input_paths(settings, root):
    """Map location-only roots, longest first so a parent cannot mask a child.

    Keep suffixes and flags intact: moving DerivedData or a checkout must not
    look like a product change, but changing an include path within either must.
    """
    paths = [(str(root), "<source>"), (str(Path(root).resolve()), "<source>")]
    for key, token in (("SRCROOT", "<source>"), ("SOURCE_ROOT", "<source>"),
                       ("PROJECT_DIR", "<source>"), ("BUILD_DIR", "<build>"),
                       ("BUILD_ROOT", "<build>"), ("SYMROOT", "<build>"),
                       ("OBJROOT", "<intermediates>"), ("DERIVED_DATA_DIR", "<derived-data>"),
                       ("DEVELOPER_DIR", "<developer>"),
                       ("HOME", "<home>")):
        path = settings.get(key, "")
        if isinstance(path, str) and path.startswith("/"):
            paths.append((path, token))
            if key in ("BUILD_DIR", "OBJROOT") and "/Build/" in path:
                paths.append((path.rsplit("/Build/", 1)[0], "<derived-data>"))
    paths.append((str(Path.home()), "<home>"))
    return sorted(dict(paths).items(), key=lambda pair: len(pair[0]), reverse=True)


def effective_inputs(root=ROOT, bundle_version=None):
    """Resolve rather than guess inherited signing and compiler settings.

    Capture every flag plus signing class/hash, versions and custom WGEX switches per
    target. Paths are checkout/build-root local and are normalised for comparison.
    No environment dump, certificates, keys or provisioning contents are retained.
    """
    version = os.environ.get("WGEX_LAB_BUNDLE_VERSION", "") if bundle_version is None else bundle_version
    records = json.loads(command(["xcodebuild", "-showBuildSettings", "-json", *build_arguments(version)], root))
    targets = {}
    keys = {"CONFIGURATION", "CURRENT_PROJECT_VERSION", "MARKETING_VERSION", "PRODUCT_BUNDLE_IDENTIFIER",
            "SWIFT_VERSION", "SWIFT_ACTIVE_COMPILATION_CONDITIONS", "GCC_PREPROCESSOR_DEFINITIONS",
            "SWIFT_OPTIMIZATION_LEVEL", "GCC_OPTIMIZATION_LEVEL", "SDKROOT", "SDK_VERSION",
            "MACOSX_DEPLOYMENT_TARGET", "ARCHS", "SWIFT_COMPILATION_MODE", "ENABLE_HARDENED_RUNTIME",
            "ENABLE_TESTABILITY", "DEBUG_INFORMATION_FORMAT", "DEAD_CODE_STRIPPING",
            "WGEX_BUNDLE_ID_BASE", "WGEX_LAB_BUILD", "WGEX_OFFLINE", "WGEX_OWN_MAC_BUILD",
            "WGEX_RESTRICTED_ENTITLEMENTS", "WGEX_ENTITLEMENTS_VARIANT", "WGEX_MAC_APP_GROUP"}
    for record in records:
        settings = record["buildSettings"]
        replacements = input_paths(settings, root)
        selected = {}
        for key, value in settings.items():
            if key == "CODE_SIGN_IDENTITY":
                continue  # Common names must never enter a committed verdict.
            if key in keys or key.endswith("FLAGS") or key.startswith(("CODE_SIGN", "LAUNCH_CONSTRAINT_", "PROVISIONING_PROFILE")):
                if not isinstance(value, str):
                    raise ValueError("buildInputs: unsupported setting value")
                for path, token in replacements:
                    if path:
                        value = re.sub(re.escape(path) + r"(?=/|[\s\"']|$)", lambda match: token, value)
                selected[key] = value
        identity = settings.get("CODE_SIGN_IDENTITY")
        fingerprint = settings.get("EXPANDED_CODE_SIGN_IDENTITY", "")
        if not isinstance(fingerprint, str):
            raise ValueError("buildInputs: signing certificate SHA-1 missing")
        fingerprint = fingerprint.lower()
        if not fingerprint and isinstance(identity, str) and CDHASH.fullmatch(identity.lower()):
            fingerprint = identity.lower()
        if identity == "-" and fingerprint in ("", "-"):
            fingerprint = "-"  # Ad hoc signing has no certificate.
        elif not isinstance(identity, str) or not identity or not CDHASH.fullmatch(fingerprint):
            raise ValueError("buildInputs: signing certificate SHA-1 missing")
        selected["CODE_SIGN_IDENTITY"] = "own-mac" if settings.get("WGEX_OWN_MAC_BUILD") == "1" else "lab"
        selected["EXPANDED_CODE_SIGN_IDENTITY"] = fingerprint
        targets[record["target"]] = selected
    result = dict(configuration="Lab", compilationConditions=CONDITIONS,
                  bundleVersionOverride=version, targets=targets)
    validate_inputs(result)
    return result


def validate_inputs(inputs):
    if not isinstance(inputs, dict) or inputs.get("configuration") != "Lab" or inputs.get("compilationConditions") != CONDITIONS:
        raise ValueError("buildInputs: missing Lab configuration or compilation flags")
    version = inputs.get("bundleVersionOverride")
    if not isinstance(version, str) or (version and not re.fullmatch(r"[1-9][0-9]*", version)):
        raise ValueError("buildInputs: missing bundle-version override")
    targets = inputs.get("targets")
    if not isinstance(targets, dict) or any(target not in targets for target in BUILD_TARGETS):
        raise ValueError("buildInputs: missing target settings")
    for settings in targets.values():
        if not isinstance(settings, dict) or settings.get("CONFIGURATION") != "Lab":
            raise ValueError("buildInputs: target is not Lab")
        for key in ("CODE_SIGN_IDENTITY", "CURRENT_PROJECT_VERSION", "SWIFT_ACTIVE_COMPILATION_CONDITIONS"):
            if not isinstance(settings.get(key), str) or not settings[key]:
                raise ValueError("buildInputs: missing " + key)
        if settings["CODE_SIGN_IDENTITY"] not in ("lab", "own-mac"):
            raise ValueError("buildInputs: invalid signing class")
        fingerprint = settings.get("EXPANDED_CODE_SIGN_IDENTITY")
        if not isinstance(fingerprint, str) or (fingerprint != "-" and not CDHASH.fullmatch(fingerprint)):
            raise ValueError("buildInputs: missing signing certificate SHA-1")
        if "WGEX_LAB_BUILD" not in settings["SWIFT_ACTIVE_COMPILATION_CONDITIONS"].split():
            raise ValueError("buildInputs: target lacks WGEX_LAB_BUILD")


def binary_hashes(app, root=ROOT):
    command(["codesign", "--verify", "--deep", "--strict", str(app)], root)
    hashes = {}
    for key, relative in BINARIES.items():
        binary = str(app / relative)
        command(["codesign", "--verify", "--strict", binary], root)
        # codesign writes display output to stderr, including on success.
        result = subprocess.run(["codesign", "-d", "--verbose=4", binary], cwd=root,
                                capture_output=True, timeout=30, check=False)
        matches = re.findall(rb"^CDHash=([0-9a-f]{40})$", result.stderr, re.M)
        if result.returncode or len(matches) != 1:
            raise ValueError("artefacts: unreadable " + key + " code-directory hash")
        hashes[key] = matches[0].decode()
    return hashes


def build_provenance(root=ROOT, bundle_version=None):
    return dict(sourceCommit=source_commit(root), buildConfiguration="Lab", buildInputs=effective_inputs(root, bundle_version))


def receipt_path(app, pending=False):
    return Path(str(app) + (".lab-provenance.pending.json" if pending else ".lab-provenance.json"))


def inspect_build(app, root=ROOT):
    receipt = json.loads(receipt_path(app).read_text())
    validate_inputs(receipt.get("buildInputs"))
    current = build_provenance(root, receipt["buildInputs"]["bundleVersionOverride"])
    if any(receipt.get(key) != value for key, value in current.items()):
        raise ValueError("buildInputs/sourceCommit: Lab receipt differs from checkout")
    if receipt.get("artefacts") != binary_hashes(app, root):
        raise ValueError("artefacts: Lab receipt differs from build")
    return receipt


def record_build(app, phase, root=ROOT):
    current = build_provenance(root)
    if phase == "finish":
        if json.loads(receipt_path(app, True).read_text()) != current:
            raise ValueError("buildInputs/sourceCommit: changed during build")
        current["artefacts"] = binary_hashes(app, root)
    path = receipt_path(app, phase == "prepare")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")


def bundle_version(inputs):
    """The one CURRENT_PROJECT_VERSION every build target carries, as an integer; None when targets disagree or it is unset."""
    try:
        versions = {settings["CURRENT_PROJECT_VERSION"] for settings in inputs["targets"].values()}
    except (KeyError, TypeError, AttributeError):
        return None
    value = versions.pop() if len(versions) == 1 else None
    return int(value) if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) else None


def without_version(inputs):
    value = json.loads(json.dumps(inputs))
    value.pop("bundleVersionOverride", None)
    for settings in value.get("targets", {}).values():
        settings.pop("CURRENT_PROJECT_VERSION", None)
    return value


def update_errors(record, root=ROOT, product_unchanged=False):
    """M5.3-07 only: the updated bundle's own receipt and the hashes found installed after the update.

    The update must be a Lab build of the same source commit with the same effective inputs except a higher
    CURRENT_PROJECT_VERSION, every binary must differ from the base build, and the guest must run exactly it.
    """
    update = record.get("update")
    if not isinstance(update, dict):
        return ["update: receipt and installed hashes missing"]
    errors = []
    if update.get("buildConfiguration") != "Lab":
        errors.append("update: buildConfiguration must be Lab")
    try:
        validate_inputs(update.get("buildInputs"))
    except ValueError as error:
        errors.append("update: " + str(error))
        return errors
    if update.get("sourceCommit") != record.get("sourceCommit"):
        errors.append("update: sourceCommit differs from the base build")
    for name in ("artefacts", "installed"):
        hashes = update.get(name)
        if not isinstance(hashes, dict) or any(not isinstance(hashes.get(key), str) or not CDHASH.fullmatch(hashes[key]) for key in BINARIES):
            errors.append("update: " + name + " missing code-directory hashes")
    if update.get("installed") != update.get("artefacts"):
        errors.append("update: installed differs from the update artefacts")
    base = record.get("artefacts") if isinstance(record.get("artefacts"), dict) else {}
    artefacts = update.get("artefacts") if isinstance(update.get("artefacts"), dict) else {}
    if any(artefacts.get(key) == base.get(key) for key in BINARIES):
        errors.append("update: artefacts must all differ from the base build")
    version, override = bundle_version(update["buildInputs"]), update["buildInputs"]["bundleVersionOverride"]
    base_version = bundle_version(record.get("buildInputs"))
    if version is None or override != str(version) or base_version is None or version <= base_version:
        errors.append("update: CURRENT_PROJECT_VERSION must be an override above the base build's")
    if update.get("bundleVersion") != str(version):
        errors.append("update: installed bundle version differs from the update build")
    if isinstance(record.get("buildInputs"), dict) and without_version(update["buildInputs"]) != without_version(record["buildInputs"]):
        errors.append("update: buildInputs differ from the base build beyond the bundle version")
    if product_unchanged and not errors:
        try:
            if update["buildInputs"] != effective_inputs(root, override):
                errors.append("product-unchanged: effective update buildInputs changed")
        except (ValueError, OSError, subprocess.TimeoutExpired, KeyError, TypeError, json.JSONDecodeError):
            errors.append("update: buildInputs verification failed")
    return errors


def provenance_errors(record, guest_os, root=ROOT, since=None, after_tasks=(), product_unchanged=False):
    errors = []
    if record.get("row") == UPDATE_ROW:
        errors.extend(update_errors(record, root, product_unchanged))
    elif "update" in record:
        errors.append("update: only " + UPDATE_ROW + " may install a second bundle")
    if record.get("buildConfiguration") != "Lab":
        errors.append("buildConfiguration must be Lab")
    guest = record.get("guestOS")
    if not isinstance(guest, dict) or not isinstance(guest.get("buildVersion"), str) or not guest["buildVersion"]:
        errors.append("guestOS.buildVersion missing")
    version = guest.get("productVersion") if isinstance(guest, dict) else None
    if not isinstance(version, str) or not re.fullmatch(re.escape(guest_os) + r"(?:\.[0-9]+)*", version):
        errors.append("guestOS.productVersion major differs from --guest-os")
    for name in ("artefacts", "installed"):
        hashes = record.get(name)
        if not isinstance(hashes, dict) or any(not isinstance(hashes.get(key), str) or not CDHASH.fullmatch(hashes[key]) for key in BINARIES):
            errors.append(name + " missing code-directory hashes")
    if record.get("installed") != record.get("artefacts"):
        errors.append("installed differs from artefacts")
    try:
        validate_inputs(record.get("buildInputs"))
    except ValueError as error:
        errors.append(str(error))
    source = record.get("sourceCommit")
    if not isinstance(source, str) or not COMMIT.fullmatch(source):
        errors.append("sourceCommit missing or invalid")
        return errors
    try:
        if not ancestor(source, "HEAD", root):
            errors.append("sourceCommit is not an ancestor of HEAD")
        # A task branch's orphan commit must never stand in for main provenance.
        if not ancestor(source, "main", root):
            errors.append("sourceCommit is off main")
        if since:
            lower = git("rev-parse", "--verify", since + "^{commit}", root=root)
            if not ancestor(lower, source, root):
                errors.append("sourceCommit precedes --since " + since)
        for task in after_tasks:
            # Parse actual trailers, not a subject/body substring or a side branch.
            history = git("log", "--first-parent", "--format=%H%x09%(trailers:key=Plan-Task,valueonly,separator=%x2c)", "HEAD", root=root)
            anchors = [line.split("\t", 1)[0] for line in history.splitlines()
                       if "\t" in line and task in line.split("\t", 1)[1].split(",")]
            if not anchors:
                errors.append("missing Plan-Task: " + task)
            elif not all(ancestor(anchor, source, root) for anchor in anchors):
                errors.append("sourceCommit precedes --after-task " + task)
        if product_unchanged:
            if product_changes(source, "HEAD", root) or product_changes(source, root=root):
                errors.append("product-unchanged: product paths changed")
            if record.get("buildInputs") != effective_inputs(root, record["buildInputs"]["bundleVersionOverride"]):
                errors.append("product-unchanged: effective buildInputs changed")
    except (ValueError, OSError, subprocess.TimeoutExpired, KeyError, TypeError, json.JSONDecodeError):
        errors.append("sourceCommit/buildInputs verification failed")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT / "Tests/Reports/v2")
    parser.add_argument("--guest-os")
    parser.add_argument("--since")
    parser.add_argument("--after-task", action="append", default=[])
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--product-unchanged", action="store_true")
    parser.add_argument("--catalogue-only", action="store_true")
    parser.add_argument("--rehearsal")
    parser.add_argument("--inspect-build", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--prepare-build", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--finish-build", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("rows", nargs="*")
    args = parser.parse_args(argv)
    for phase in ("inspect", "prepare", "finish"):
        app = getattr(args, phase + "_build")
        if app is not None:
            try:
                if phase == "inspect":
                    print(json.dumps(inspect_build(app), sort_keys=True))
                else:
                    record_build(app, phase)
                return 0
            except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
                print("build: " + phase + " provenance failed", file=sys.stderr)
                return 1
    if not args.catalogue_only and (not args.guest_os or not re.fullmatch(r"[1-9][0-9]*", args.guest_os)):
        parser.error("--guest-os MAJOR is required")
    if args.rehearsal and (args.rows or args.scope or args.catalogue_only):
        parser.error("--rehearsal selects one record instead of rows, scope or catalogue")
    rows = args.rows[:]
    if args.scope:
        try:
            rows.extend(line.split("#", 1)[0].strip() for line in args.scope.read_text().splitlines()
                        if line.split("#", 1)[0].strip())
        except OSError:
            print("scope: unreadable file", file=sys.stderr)
            return 1
    rows = list(dict.fromkeys([args.rehearsal] if args.rehearsal else rows))
    if not rows:
        print("rows: empty row set", file=sys.stderr)
        return 1
    catalogue = {}
    if args.catalogue_only:
        try:
            catalogue = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
        except (OSError, ValueError, KeyError, TypeError):
            print("catalogue: missing or invalid", file=sys.stderr)
            return 1
    failed = False
    for row in rows:
        errors = []
        if not IDENTIFIER.fullmatch(row) or row in (".", ".."):
            errors.append("invalid row identifier")
        elif args.catalogue_only:
            if row not in catalogue:
                errors.append("catalogue row missing")
            elif "gap" in catalogue[row]:
                errors.append("catalogue gap declared")
        else:
            try:
                record = json.loads((args.root / row / "verdict.json").read_text())
                if not isinstance(record, dict):
                    raise ValueError("record must be an object")
                if record.get("row") != row:
                    errors.append("row differs from directory")
                required = REHEARSAL_CHECKS if args.rehearsal else ("expectationsMet", "liveAcceptance", "rowCompleted")
                for key in required:
                    if record.get(key) is not True:
                        errors.append(key + " must be true")
                if args.install and (not isinstance(record.get("installation"), dict) or record["installation"].get("installCompleted") is not True):
                    errors.append("installation.installCompleted must be true")
                errors.extend(provenance_errors(record, args.guest_os, since=args.since,
                                                after_tasks=args.after_task, product_unchanged=args.product_unchanged))
            except (OSError, ValueError, TypeError):
                errors.append("verdict.json missing or invalid")
        for error in errors:
            print(row + ": " + error, file=sys.stderr)
        failed |= bool(errors)
    if not failed:
        print("PASS: " + ", ".join(rows))
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
