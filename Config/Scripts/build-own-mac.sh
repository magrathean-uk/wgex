#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Offline, opt-in own-Mac Release build. Never prints or saves certificate hashes.
# SHELLOPTS can enable tracing before this script starts.
set +x
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$root"
base=com.magrathean.WGEXApp
fail() {
  echo "build-own-mac: $*" >&2
  exit 1
}
redact() {
  python3 -I -u -c 'import re, sys
for line in sys.stdin.buffer:
    sys.stdout.buffer.write(re.sub(rb"(?i)[0-9a-f]{40}", b"[redacted]", line))
    sys.stdout.buffer.flush()'
}
xcodebuild_filter() {
  # Withhold Xcode's shell-phase exports, including multiline quoted values.
  LC_ALL=C awk '
    function open_quote(text) { if (text !~ /^"/) return 0; text=substr(text,2); gsub(/\\./,"",text); return text !~ /"/ }
    function closes(text) { sub(/\r$/, "", text); gsub(/\\./,"",text); return text ~ /"$/ }
    function open_name(text) { sub(/^[ \t]*export "/,"",text); sub(/\r$/,"",text); gsub(/\\./,"",text); return text !~ /"/ }
    function after_name(text) { if (!match(text,/^([^"\\]|\\.)*"\\?=/)) return -1; return RLENGTH }
    function resolve(value) { sub(/\r$/, "", value); if (open_quote(value)) skip=1 }
    skip { if (closes($0)) skip=0; next }
    name { cut=after_name($0); if (cut>=0) { name=0; resolve(substr($0,cut+1)) }; next }
    match($0,/^[ \t]*export ("([^"\\]|\\.)*"|[^ \t=]+)\\?=/) { resolve(substr($0,RLENGTH+1)); next }
    /^[ \t]*export "/ && open_name($0) { name=1; next }
    { print; fflush() }
  ' | redact
}
valid_name() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
[[ -n "${WGEX_OWN_MAC_OUTPUT_ROOT:-}" ]] || fail 'WGEX_OWN_MAC_OUTPUT_ROOT is required: choose a private internal-disk directory outside the repository'
[[ "${CLEAN_DEV_MODE:-}" == external ]] || fail 'external storage mode required'
[[ -n "${CLEAN_DEV_BUILDS:-}" && "$CLEAN_DEV_BUILDS" == /* ]] || fail 'absolute CLEAN_DEV_BUILDS required'

# Signed products and temporary files must be private and internal from their
# first write. The caller supplies one run root for fresh A/B attempts; shared
# caches and all routing variables retain their inherited values.
private_paths() {
  python3 -I -c 'from pathlib import Path
import os, stat, sys
action, name = sys.argv[1:]
def absolute(value):
    assert value and value.startswith("/") and ".." not in Path(value).parts
    return Path(value)
def check_dir(path):
    for part in (path, *path.parents):
        info = part.lstat()
        assert stat.S_ISDIR(info.st_mode)
        if part == base or part.is_relative_to(base):
            assert info.st_dev == internal_device and info.st_uid == os.geteuid()
            assert not stat.S_IMODE(info.st_mode) & 0o077
try:
    internal_device = Path("/System/Volumes/Data").stat().st_dev
    builds = absolute(os.environ.get("CLEAN_DEV_BUILDS")).resolve(strict=True)
    assert builds.is_dir()
    routed = os.environ.get("WGEX_BUILD_ROOT")
    assert not routed or absolute(routed).resolve().is_relative_to(builds)
    output = absolute(os.environ.get("WGEX_OWN_MAC_OUTPUT_ROOT"))
    base = output.parent
    temp = absolute(os.environ.get("TMPDIR"))
    repository = Path.cwd()
    for path in (output, temp):
        assert not (path == repository or path.is_relative_to(repository) or repository.is_relative_to(path))
    assert temp != base and temp.is_relative_to(base)
    assert not (output == temp or output.is_relative_to(temp) or temp.is_relative_to(output))
    check_dir(output.parent)
    check_dir(temp)
    if os.path.lexists(output):
        check_dir(output)
    elif action == "compare":
        raise ValueError("missing output root")
    if action == "allocate":
        if not os.path.lexists(output):
            os.mkdir(output, 0o700)
        check_dir(output)
        os.mkdir(output / name, 0o700)
    elif action == "build":
        assert not os.path.lexists(output / name)
    print(output)
except (OSError, ValueError, AssertionError):
    sys.exit("build-own-mac: invalid private output root, temporary directory or existing attempt")' "$@"
}

if [[ "${1:-}" == compare ]]; then
  [[ $# == 3 ]] || fail 'usage: build-own-mac compare A B'
  valid_name "$2" && valid_name "$3" && [[ "$2" != "$3" ]] || fail 'invalid attempt names'
  namespace="$(private_paths compare '')" || exit 1
  a="$namespace/$2"
  b="$namespace/$3"
  for dir in "$a" "$b"; do
    python3 -I -c 'from pathlib import Path
import sys
try:
    p, root = Path(sys.argv[1]), Path(sys.argv[2]).resolve(strict=True)
    assert not p.is_symlink() and p.resolve(strict=True).is_relative_to(root) and p.is_dir()
except (OSError, ValueError, AssertionError):
    sys.exit("build-own-mac: invalid comparison attempt")' "$dir" "$namespace" || exit 1
    [[ -f "$dir/PASSED" && "$(cat "$dir/PASSED")" == passed ]] || fail 'comparison requires two passed attempts'
  done
  for name in app executable embedded-daemon embedded-cli daemon cli; do
    [[ -s "$a/$name.dr" && -s "$b/$name.dr" && -s "$a/$name.cdhash.sha256" && -s "$b/$name.cdhash.sha256" ]] || fail "missing evidence for $name"
    cmp -s "$a/$name.dr" "$b/$name.dr" || fail "designated requirement changed for $name"
    cmp -s "$a/$name.cdhash.sha256" "$b/$name.cdhash.sha256" && fail "CDHash did not change for $name"
  done
  echo 'build-own-mac: designated requirements match and all CDHashes changed'
  exit 0
fi
[[ $# -le 1 ]] || fail 'usage: build-own-mac [attempt] | compare A B'
attempt_name="${1:-A}"
valid_name "$attempt_name" || fail 'invalid attempt name'
namespace="$(private_paths build "$attempt_name")" || exit 1
attempt="$namespace/$attempt_name"

# The team, leaf common name and profile are the maintainer's own and live only
# in the git-ignored Config/Local.xcconfig (template: Config/Local.xcconfig.example).
local_values="$(python3 -I -c 'import os, pathlib, re, sys, uuid
try:
    text = pathlib.Path(sys.argv[1]).read_text()
    def one(name):
        found = re.findall(r"(?m)^[ \t]*" + name + r"[ \t]*=[ \t]*(.*?)[ \t]*$", text)
        assert len(found) == 1
        return found[0]
    team, leaf, profile = one("WGEX_TEAM"), one("WGEX_OWN_MAC_LEAF"), one("WGEX_OWN_MAC_PROFILE")
    assert re.fullmatch(r"[A-Z0-9]{10}", team)
    assert re.fullmatch(r"Apple Development: [A-Za-z0-9 ._,@+-]+ \([A-Z0-9]{10}\)", leaf)
    for value in (profile, os.environ.get("WGEX_OWN_MAC_PROFILE_UUID", profile)):
        assert re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value)
        assert str(uuid.UUID(value)) == value.lower()
    print(team)
    print(leaf)
    print(os.environ.get("WGEX_OWN_MAC_PROFILE_UUID", profile))
except (OSError, ValueError, AssertionError):
    sys.exit("build-own-mac: Config/Local.xcconfig must define WGEX_TEAM, WGEX_OWN_MAC_LEAF and WGEX_OWN_MAC_PROFILE once each (see Config/Local.xcconfig.example)")' Config/Local.xcconfig)" || exit 1
{
  IFS= read -r team
  IFS= read -r cn
  IFS= read -r profile_uuid
} <<<"$local_values"
[[ "${WGEX_OWN_MAC_IDENTITY_SHA1:-}" =~ ^[0-9A-Fa-f]{40}$ ]] || fail 'WGEX_OWN_MAC_IDENTITY_SHA1 must be a certificate SHA-1'
[[ -z "${WGEX_OWN_MAC_PROFILE:-}" || "$WGEX_OWN_MAC_PROFILE" == "$profile_uuid" ]] || fail 'wrong own-Mac profile override'
[[ "${WGEX_OWN_MAC_BUILD_NUMBER:-}" =~ ^[0-9]+$ ]] || fail 'WGEX_OWN_MAC_BUILD_NUMBER must be an integer'
[[ "${WGEX_LAB_BUILD-0}" == 0 ]] || fail 'WGEX_LAB_BUILD is forbidden'
[[ -z "${WGEX_ENGINE_TEST_SUPPORT+x}" ]] || fail 'WGEX_ENGINE_TEST_SUPPORT is forbidden'
[[ -z "${XCODE_XCCONFIG_FILE+x}" ]] || fail 'XCODE_XCCONFIG_FILE is forbidden'
[[ -z "${CONFIGURATION:-}" || "$CONFIGURATION" == Release ]] || fail 'only Release is permitted'

# Restrict all subsequent tools too: Git and the source-digest checker run
# before Xcode, and must not inherit redirects or build-setting overrides.
while IFS= read -r name; do
  case "$name" in
    PATH | HOME | TMPDIR | DEVCACHE | DEVELOPER_DIR | LANG | LC_* | CLEAN_DEV_* | CLEAN_DEVELOPMENT_* | CODEX_THREAD_ID | CLAUDE_CODE_SESSION_ID | WGEX_BUILD_ROOT | WGEX_OWN_MAC_OUTPUT_ROOT | WGEX_OWN_MAC_IDENTITY_SHA1 | WGEX_OWN_MAC_PROFILE_UUID | WGEX_OWN_MAC_BUILD_NUMBER | WGEX_OWN_MAC_PROFILE) ;;
    *) unset "$name" || fail "could not drop inherited $name" ;;
  esac
done < <(compgen -e)

# Git's normal untracked set excludes generated files and the explicitly ignored design pack.
if ! git status --porcelain=v1 -z --untracked-files=all | python3 -I -c 'import sys
entries = sys.stdin.buffer.read().split(b"\0")
allowed = (b"AGENTS.md", b"CLAUDE.md")
for entry in filter(None, entries):
    status, path = entry[:2], entry[3:]
    if status != b"??" or not (path in allowed or path.startswith((b"Design/", b"Packages/WGEXEngine/Binary/"))):
        sys.exit(1)'; then
  fail 'working tree must be clean'
fi

# Work only with public certificates and decoded installed profiles, in memory.
profile_path="$(python3 -I -c 'import base64, datetime, hashlib, os, pathlib, plistlib, re, subprocess, sys
team, base, cn, profile_uuid = sys.argv[1:]
wanted = os.environ["WGEX_OWN_MAC_IDENTITY_SHA1"].upper()
def run(args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
def fail(message):
    sys.exit("build-own-mac: " + message)
def covers(patterns, value):
    return isinstance(patterns, list) and any(
        isinstance(pattern, str) and (pattern == value or
        (pattern.endswith(".*") and "*" not in pattern[:-1] and
         value.startswith(pattern[:-1]) and len(value) > len(pattern) - 1)) for pattern in patterns)
try:
    identities = run(["security", "find-identity", "-v", "-p", "codesigning"]).decode("utf-8", "replace")
    matches = re.findall(r"(?m)^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+\"([^\"]+)\"\s*$", identities)
    selected = [name for digest, name in matches if digest.upper() == wanted]
    if len(selected) != 1 or selected[0] != cn or not selected[0].startswith("Apple Development:"):
        fail("missing, ambiguous or wrong Apple Development identity")
    certs = run(["security", "find-certificate", "-a", "-p", "-c", cn])
    pems = re.findall(rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", certs, re.S)
    der = [base64.b64decode(re.sub(rb"\s+", b"", pem), validate=True) for pem in pems]
    cert = [item for item in der if hashlib.sha1(item).hexdigest().upper() == wanted]
    if len(cert) != 1:
        fail("public certificate missing or ambiguous")
    subject = run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253"], cert[0]).decode()
    if not re.search(r"(?:^|,)OU=" + re.escape(team) + r"(?:,|$)", subject.strip().removeprefix("subject=")):
        fail("certificate team does not match")
    if "CN=" + cn not in subject:
        fail("certificate common name does not match")
    path = pathlib.Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles" / (profile_uuid + ".provisionprofile")
    data = plistlib.loads(run(["security", "cms", "-D", "-i", str(path)]))
    ent = data["Entitlements"]
    appid = team + "." + base
    ids = [ent[k] for k in ("application-identifier", "com.apple.application-identifier") if k in ent]
    expires = data["ExpirationDate"]
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    valid = (data["UUID"].lower() == profile_uuid.lower() and data["TeamIdentifier"] == [team] and data["ApplicationIdentifierPrefix"] == [team]
             and isinstance(data["Platform"], list) and "OSX" in data["Platform"]
             and ids and all(value == appid for value in ids)
             and ent.get("com.apple.developer.team-identifier") == team
             and covers(ent["keychain-access-groups"], appid)
             and covers(ent["com.apple.security.application-groups"], appid)
             and expires > now
             and cert[0] in data["DeveloperCertificates"])
    if not valid:
        fail("profile team, identifiers, entitlements, expiry or certificate do not match")
    print(path)
except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError, plistlib.InvalidFileException):
    fail("could not validate public identity or installed profile")' "$team" "$base" "$cn" "$profile_uuid")" || exit 1
python3 -I Engine/scripts/source-digest.py --verify "$root/Packages/WGEXEngine/Binary" 2>&1 | redact || fail 'engine source digest verification failed'

private_paths allocate "$attempt_name" >/dev/null || exit 1
# xcodegen itself does not resolve packages or call xcodebuild.
xcodegen generate --spec project.yml --quiet 2>&1 | redact | tee "$attempt/generation.log"
bash Config/Scripts/generate-build-identifiers.sh --configuration Release 2>&1 | redact | tee -a "$attempt/generation.log"
# The pinned team and leaf reach the daemon requirement only through this generated, git-ignored file.
identity_dir=Packages/WGEXBackendMac/Sources/WGEXDaemonProtocol/Generated
mkdir -p "$identity_dir"
printf '// Generated by Config/Scripts/build-own-mac.sh from Config/Local.xcconfig. Git-ignored; do not edit.\n#if WGEX_OWN_MAC_BUILD\n    package enum OwnMacIdentity {\n        package static let team = "%s"\n        package static let leaf = "%s"\n    }\n#endif\n' "$team" "$cn" >"$identity_dir/OwnMacIdentity.generated.swift"
# Xcode persists build activity and database files containing signing arguments.
# Only paths inside this new attempt are removed; refuse symlinked ancestors.
cleanup_derived() {
  local part
  for part in "$namespace" "$attempt" "$attempt/derived-data" "$attempt/derived-data/Logs" "$attempt/derived-data/Logs/Build" \
    "$attempt/derived-data/Build" "$attempt/derived-data/Build/Intermediates.noindex" \
    "$attempt/derived-data/Build/Intermediates.noindex/XCBuildData"; do
    [[ ! -L "$part" ]] || {
      echo 'build-own-mac: refusing symlink in build cleanup' >&2
      return 1
    }
  done
  /bin/rm -rf -- "$attempt/derived-data/Logs/Build" "$attempt/derived-data/Build/Intermediates.noindex/XCBuildData"
}
# shellcheck disable=SC2154 # status is assigned inside the trap
trap 'status=$?; ((status != 0)) || status=1; cleanup_derived || status=1; exit "$status"' EXIT
set +e
python3 -I -c 'import os, sys
names = {"PATH", "HOME", "TMPDIR", "DEVCACHE", "DEVELOPER_DIR", "LANG",
         "CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "WGEX_BUILD_ROOT",
         "WGEX_OWN_MAC_IDENTITY_SHA1", "WGEX_OWN_MAC_BUILD_NUMBER", "WGEX_OWN_MAC_PROFILE_UUID"}
child = {key: value for key, value in os.environ.items()
         if key in names or key.startswith(("LC_", "CLEAN_DEV_", "CLEAN_DEVELOPMENT_"))}
child["WGEX_OWN_MAC_SIGNING"] = "1"
child["WGEX_OWN_MAC_BUILD"] = "1"
os.execvpe("xcodebuild", ["xcodebuild", *sys.argv[1:]], child)' build -project WGEX.xcodeproj -scheme WGEX-Mac -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath "$attempt/derived-data" \
  -xcconfig Config/OwnMacRelease.xcconfig -disableAutomaticPackageResolution \
  "SWIFT_ACTIVE_COMPILATION_CONDITIONS=\$(inherited) WGEX_OWN_MAC_BUILD" \
  "CURRENT_PROJECT_VERSION=$WGEX_OWN_MAC_BUILD_NUMBER" "WGEX_OWN_MAC_PROFILE=$profile_uuid" 2>&1 | xcodebuild_filter | tee "$attempt/build.log"
results=("${PIPESTATUS[@]}")
set -e
cleanup_derived || fail 'could not remove build activity and database files'
trap - EXIT
if ((results[0] != 0)); then
  if grep -Eiq 'errSecInternalComponent|user interaction (is )?not allowed|-25308|interaction with the security server' "$attempt/build.log"; then
    echo 'NEED-USER: signing needs the maintainer at the keychain prompt' >&2
    exit 77
  fi
  fail 'xcodebuild failed'
fi
((results[1] == 0 && results[2] == 0)) || fail 'redacted build log failed'

products="$attempt/derived-data/Build/Products"
app="$products/Release/WGEX.app"
embedded_profile="$app/Contents/embedded.provisionprofile"
if [[ ! -f "$embedded_profile" ]] || ! cmp -s "$profile_path" "$embedded_profile"; then
  fail 'embedded profile differs from installed profile'
fi
security cms -D -i "$embedded_profile" 2>/dev/null | python3 -I -c 'import plistlib, sys
try:
    assert plistlib.loads(sys.stdin.buffer.read())["UUID"].lower() == sys.argv[1].lower()
except (ValueError, KeyError, TypeError, AttributeError, AssertionError, plistlib.InvalidFileException):
    sys.exit(1)' "$profile_uuid" || fail 'embedded profile UUID does not match'
mkdir -m 700 "$attempt/certificates"
paths=("$app" "$app/Contents/MacOS/WGEX" "$app/Contents/MacOS/WGEXDaemon" "$app/Contents/Helpers/wgex" "$products/Release/WGEXDaemon" "$products/Release/wgex")
names=(app executable embedded-daemon embedded-cli daemon cli)
ids=("$base" "$base" "$base.daemon" "$base.cli" "$base.daemon" "$base.cli")
for index in 0 1 2 3 4 5; do
  path="${paths[$index]}"
  name="${names[$index]}"
  id="${ids[$index]}"
  [[ -e "$path" ]] || fail "missing product: $name"
  if ! info="$(codesign -dv --verbose=4 "$path" 2>&1)"; then fail "signature inspection failed: $name"; fi
  printf '%s\n' "$info" | redact >"$attempt/$name.signature.log"
  grep -Fxq "Identifier=$id" <<<"$info" || fail "wrong identifier: $name"
  grep -Fxq "Authority=$cn" <<<"$info" || fail "wrong authority: $name"
  grep -Fxq "TeamIdentifier=$team" <<<"$info" || fail "wrong team: $name"
  grep -Eq 'flags=.*\(.*runtime' <<<"$info" || fail "missing hardened runtime: $name"
  ! grep -Eq '^Timestamp=' <<<"$info" || fail "secure timestamp present: $name"
  printf '%s\n' "$info" | python3 -I -c 'import hashlib, re, sys
m = re.findall(r"(?mi)^CDHash=([0-9a-f]{40})\s*$", sys.stdin.read())
if len(m) != 1: sys.exit(1)
print(hashlib.sha256(m[0].lower().encode()).hexdigest())' >"$attempt/$name.cdhash.sha256" || fail "missing CDHash: $name"
  if ! requirements="$(codesign -d -r- "$path" 2>&1)"; then fail "requirement inspection failed: $name"; fi
  printf '%s\n' "$requirements" | redact >"$attempt/$name.requirements.log"
  printf '%s\n' "$requirements" | python3 -I -c 'import re, sys
lines = [line for line in sys.stdin.read().splitlines() if line.startswith("designated ")]
if len(lines) != 1 or re.search(r"(?i)cdhash|[0-9a-f]{40}", lines[0]): sys.exit(1)
line = lines[0]
if not line.startswith("designated => "): sys.exit(1)
parts = re.split(r"\s+and\s+", line[len("designated => "):])
q = chr(34)
required = {f"identifier {q}{sys.argv[1]}{q}", "anchor apple generic",
            f"certificate leaf[subject.CN] = {q}{sys.argv[3]}{q}",
            "certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"}
allowed = required | {f"certificate leaf[subject.OU] = {q}{sys.argv[2]}{q}"}
if not required.issubset(parts) or len(parts) != len(set(parts)) or not set(parts).issubset(allowed): sys.exit(1)
print(line)' "$id" "$team" "$cn" >"$attempt/$name.dr" || fail "invalid designated requirement: $name"
  printf 'identifier "%s" and anchor apple generic and certificate leaf[subject.OU] = "%s" and certificate leaf[subject.CN] = "%s"\n' "$id" "$team" "$cn" >"$attempt/$name.requirement"
  codesign --verify --strict --deep "$path" 2>&1 | redact | tee "$attempt/$name.verify.log" || fail "strict verification failed: $name"
  codesign --verify --strict -R "$attempt/$name.requirement" "$path" 2>&1 | redact | tee -a "$attempt/$name.verify.log" || fail "identity policy failed: $name"
  codesign -d "--extract-certificates=$attempt/certificates/$name" "$path" 2>&1 | redact | tee -a "$attempt/$name.verify.log" || fail "certificate extraction failed: $name"
  python3 -I -c 'import hashlib, os, pathlib, sys
try:
    assert hashlib.sha1(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest().upper() == os.environ["WGEX_OWN_MAC_IDENTITY_SHA1"].upper()
except (OSError, AssertionError):
    sys.exit(1)' "$attempt/certificates/${name}0" || fail "signing certificate differs from selected identity: $name"
  if ! codesign -d --entitlements - --xml "$path" 2>/dev/null | python3 -I -c 'import plistlib, sys
try:
    raw = sys.stdin.buffer.read()
    ent = plistlib.loads(raw) if raw.strip() else {}
    assert not any(k == "com.apple.security.get-task-allow" or k.startswith("com.apple.security.cs.allow-") for k in ent)
except (ValueError, AssertionError, plistlib.InvalidFileException):
    sys.exit(1)'; then fail "forbidden or unreadable entitlements: $name"; fi
done
cmp -s "$attempt/embedded-daemon.dr" "$attempt/daemon.dr" || fail 'daemon requirements differ'
cmp -s "$attempt/embedded-cli.dr" "$attempt/cli.dr" || fail 'CLI requirements differ'
security cms -D -i "$profile_path" | bash Tools/lint/check-entitlements.sh --configuration Release --products "$products" --require mac --variant full --own-mac --profile - 2>&1 | redact | tee "$attempt/entitlements.log" || fail 'entitlement check failed'
# The existing link checker appends the worktree basename to WGEX_BUILD_ROOT.
mkdir -p "$attempt/link-check/$(basename "$root")"
ln -s "$attempt/derived-data" "$attempt/link-check/$(basename "$root")/derived-data"
WGEX_BUILD_ROOT="$attempt/link-check" bash Engine/scripts/check-link.sh --release mac own-mac 2>&1 | redact | tee "$attempt/link.log" || fail 'Release link check failed'
echo "build-own-mac: checks complete; recording success ($attempt_name)"
printf 'passed\n' >"$attempt/PASSED"
