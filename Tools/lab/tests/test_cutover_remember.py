# SPDX-License-Identifier: MIT
"""M1-12b: the cutover rehearsal remembers an armed trial's resources from the replayed daemon journal, never a VM."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "Tools/lab/cutover-rehearsal.sh"
REPLAY = ROOT / "Tools/lab/tart/guest/journal-replay.pl"
# The real armed trial captured in guest run 7 (fixture SOURCE.txt). Its pfToken is compared, never printed: assertions
# that could show it use same() instead of assertEqual.
FIXTURE = ROOT / "Tools/lab/tests/fixtures/cutover-armed-run7"
PROFILE = "00000000-0000-4000-8000-000000000101"
EXPECTED = json.loads((FIXTURE / "expected-replayed.json").read_text())
CHECKPOINT_SEQUENCE = json.loads((FIXTURE / "journal.json").read_text())["journalSequence"]
# The reader cutover-rehearsal.sh used before M1-12b (guest run 6 aborted on it), minus sudo.
OLD_READER = """set -eu
sudo() { shift; "$@"; }
sudo -n plutil -extract resources.0.addresses.0 raw -o - "$j" | cut -d/ -f1 >"$stage/address"
sudo -n plutil -extract pfToken raw -o - "$j" >"$stage/token"
sudo -n plutil -extract pfTokenPID raw -o - "$j" >"$stage/pid"
sudo -n plutil -extract pfBootSession raw -o - "$j" | tr '[:lower:]' '[:upper:]' >"$stage/boot"
"""
REFERENCES = "No ALTQ support in kernel\nTOKENS:\nPID Process Name TOKEN TIMESTAMP\n4243 pfctl 9002 0 days 00:00:05\n"


def frame(body: bytes, durable: bool) -> bytes:
    """JournalRecord.encode: little-endian length (high bit = discardable bookkeeping), JSON body, SHA-256 of the body."""
    return struct.pack("<I", len(body) | (0 if durable else 0x8000_0000)) + body + hashlib.sha256(body).digest()


def records():
    return [line.encode() for line in (FIXTURE / "journal.log.jsonl").read_text().splitlines()]


def log_bytes(bodies):
    return b"".join(frame(body, json.loads(body)["durable"]) for body in bodies)


def same(test, actual, expected, what):
    """assertEqual without the diff: the values can hold the captured pf token."""
    if actual != expected:
        keys = sorted(k for k in set(actual) | set(expected) if actual.get(k) != expected.get(k)) if isinstance(actual, dict) and isinstance(expected, dict) else []
        test.fail(f"{what} differs from the fixture (values not shown){'; keys ' + ', '.join(keys) if keys else ''}")


def remember_body():
    text = SCRIPT.read_text()
    match = re.search(r"^IFS= read -r -d '' remember_body <<'REMEMBER' \|\| true\n(.*?)^REMEMBER$", text, re.S | re.M)
    if match is None:
        raise AssertionError("shared remember body not found")
    return match.group(1)


class ReplayTests(unittest.TestCase):
    """journal-replay.pl reconstructs the document the daemon restores from journal.json plus journal.log."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]))
        self.addCleanup(shutil.rmtree, self.directory)
        shutil.copy(FIXTURE / "journal.json", self.directory / "journal.json")

    def replay(self, log: bytes):
        (self.directory / "journal.log").write_bytes(log)
        return subprocess.run(["perl", str(REPLAY), str(self.directory)], capture_output=True, check=False)

    def test_armed_trial_replays_to_the_expected_document(self):
        result = self.replay(log_bytes(records()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        same(self, json.loads(result.stdout), EXPECTED, "replayed document")
        self.assertEqual((EXPECTED["journalSequence"], EXPECTED["generation"], [r["generation"] for r in EXPECTED["resources"]]), (412, 10, [10]))

    def test_the_checkpoint_alone_lacks_the_trial_resources_and_token(self):
        checkpoint = json.loads((FIXTURE / "journal.json").read_text())
        self.assertEqual(checkpoint["schemaVersion"], 2)
        self.assertIn("armed", checkpoint["cutover"]["state"])
        self.assertEqual(checkpoint["resources"], [])
        self.assertNotIn("pfToken", checkpoint)
        for key in ["resources.0.addresses.0", "pfToken"]:
            result = subprocess.run(["plutil", "-extract", key, "raw", "-o", "-", str(FIXTURE / "journal.json")], capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0, key)

    def test_a_torn_bookkeeping_tail_is_discarded(self):
        bodies = records()
        last = bodies[-1]
        self.assertFalse(json.loads(last)["durable"])
        torn = frame(last, False)[:-1] + b"\0"
        expected = self.replay(log_bytes(bodies[:-1]))
        result = self.replay(log_bytes(bodies[:-1]) + torn)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout == expected.stdout, "a torn tail is discarded (values not shown)")
        self.assertTrue(self.replay(log_bytes(bodies[:-1]) + frame(last, False)[:20]).stdout == expected.stdout, "an incomplete frame ends replay")

    def test_a_corrupt_durable_record_is_refused(self):
        bodies = records()
        index = next(n for n, body in enumerate(bodies) if json.loads(body)["durable"])
        corrupt = bytearray(log_bytes(bodies))
        offset = sum(len(frame(body, True)) for body in bodies[:index]) + 4
        corrupt[offset + 2] ^= 1
        result = self.replay(bytes(corrupt))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")

    def test_a_sequence_gap_is_refused(self):
        bodies = records()
        self.assertNotEqual(self.replay(log_bytes(bodies[:3] + bodies[4:])).returncode, 0)

    def test_records_already_in_the_checkpoint_are_skipped(self):
        stale = json.dumps({"durable": True, "removed": [], "sequence": CHECKPOINT_SEQUENCE, "set": {"pfToken": "1"}}, sort_keys=True).encode()
        result = self.replay(log_bytes([stale] + records()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["pfToken"] == EXPECTED["pfToken"], "the stale record was applied (values not shown)")

    def test_a_non_numeric_generation_is_refused_without_quoting_it(self):
        """FIX1-VERIFY N1: a numeric comparison under `use warnings` would quote the value; the helper refuses first."""
        bodies = records()
        following = CHECKPOINT_SEQUENCE + len(bodies) + 1
        bad = "NOTNUMERIC-CONTENT"
        cases = {
            "resource edit": {"durable": True, "resources": [{"generation": bad, "removed": [], "set": {}}], "sequence": following},
            "journal entry": {"durable": False, "entries": [{"action": "willApply", "generation": bad, "step": "x"}], "replaceEntries": False, "sequence": following},
            "document": {"durable": True, "removed": [], "sequence": following, "set": {"generation": bad}},
            "resource edit, decimal": {"durable": True, "resources": [{"generation": "10.5", "removed": [], "set": {}}], "sequence": following},
        }
        for name, record in cases.items():
            with self.subTest(case=name):
                body = json.dumps(record, sort_keys=True).encode()
                result = self.replay(log_bytes(bodies) + frame(body, record["durable"]))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                self.assertEqual(result.stderr, b"journal log invalid\n")
        # M1-12c VERIFY N2: a checkpoint-only fault names the checkpoint, not the log.
        checkpoint = json.loads((FIXTURE / "journal.json").read_text())
        for key, value in [("generation", bad), ("entries", bad)]:
            with self.subTest(case=f"checkpoint {key}"):
                (self.directory / "journal.json").write_text(json.dumps({**checkpoint, key: value}))
                result = self.replay(b"")
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                self.assertEqual(result.stderr, b"journal checkpoint invalid\n")
                self.assertNotIn(bad.encode(), result.stderr)

    def test_a_record_of_the_wrong_shape_is_refused_without_quoting_it(self):
        """M1-12c VERIFY N1: a string where the daemon writes an array or object would make Perl's strict-refs error quote
        it; the helper type-checks every container first and dies with a fixed message."""
        bodies = records()
        following = CHECKPOINT_SEQUENCE + len(bodies) + 1
        marker = "MARKERWORD-QUOTED"
        edit = {"generation": 10, "removed": [], "set": {}}
        cases = {
            "removed": {"durable": True, "removed": marker, "sequence": following},
            "entries": {"durable": False, "entries": marker, "replaceEntries": False, "sequence": following},
            "resources": {"durable": True, "resources": marker, "sequence": following},
            "resources[].removed": {"durable": True, "resources": [{**edit, "removed": marker}], "sequence": following},
            "resources[].set": {"durable": True, "resources": [{**edit, "set": marker}], "sequence": following},
            "previous resources": {"durable": True, "removed": [], "resources": [edit], "sequence": following, "set": {"resources": marker}},
            "previous resource": {"durable": True, "removed": [], "resources": [edit], "sequence": following, "set": {"resources": [marker]}},
            # M1-12d VERIFY N1: the generic fallback is gone; every log fault names the log.
            "set": {"durable": True, "removed": [], "sequence": following, "set": marker},
            "entries element": {"durable": False, "entries": [marker], "replaceEntries": False, "sequence": following},
            # M1-12d VERIFY N2: removed lists [String]; a container or null element is refused, not used as a key.
            "removed element object": {"durable": True, "removed": [{marker: marker}], "sequence": following},
            "removed element null": {"durable": True, "removed": [None], "sequence": following},
            "resources[].removed element object": {"durable": True, "resources": [{**edit, "removed": [{marker: marker}]}], "sequence": following},
            "resources[].removed element null": {"durable": True, "resources": [{**edit, "removed": [None]}], "sequence": following},
        }
        for name, record in cases.items():
            with self.subTest(case=name):
                body = json.dumps(record, sort_keys=True).encode()
                result = self.replay(log_bytes(bodies) + frame(body, record["durable"]))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                self.assertEqual(result.stderr, b"journal log invalid\n")
                self.assertNotIn(marker.encode(), result.stdout + result.stderr)
        # M1-12d VERIFY F1: a non-numeric journalSequence reached a numeric comparison whose warning quoted it, and a
        # "400..." value was accepted; the checkpoint is now refused first, with the run 7 log present to reach the replay.
        checkpoint = json.loads((FIXTURE / "journal.json").read_text())
        for key, value in [("journalSequence", marker), ("journalSequence", f"400{marker}"), ("journalSequence", [marker]),
                           ("entries", [marker])]:
            with self.subTest(case=f"checkpoint {key} {value!r}"):
                (self.directory / "journal.json").write_text(json.dumps({**checkpoint, key: value}))
                result = self.replay(log_bytes(bodies))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                self.assertEqual(result.stderr, b"journal checkpoint invalid\n")
                self.assertNotIn(marker.encode(), result.stdout + result.stderr)

    def test_sequences_and_generations_are_bounded_to_uint64(self):
        """FIX1-VERIFY N1: the daemon decodes these as UInt64; at most 20 digits and at most 18446744073709551615."""
        bodies = records()
        following = CHECKPOINT_SEQUENCE + len(bodies) + 1
        checkpoint = json.loads((FIXTURE / "journal.json").read_text())
        too_big = ["99999999999999999999999", "18446744073709551616", "000000000000000000001"]
        for value in too_big:
            # A bare number with leading zeros is not JSON at all (refused as journal invalid); its string form is tested.
            for raw in [json.dumps(value)] + ([value] if not value.startswith("0") else []):
                with self.subTest(case=f"checkpoint journalSequence {raw}"):
                    text = json.dumps({**checkpoint, "journalSequence": 0}).replace('"journalSequence": 0', '"journalSequence": ' + raw)
                    (self.directory / "journal.json").write_text(text)
                    result = self.replay(log_bytes(bodies))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                    self.assertEqual(result.stderr, b"journal checkpoint invalid\n")
        shutil.copy(FIXTURE / "journal.json", self.directory / "journal.json")
        for value in too_big:
            cases = {
                "generation": {"durable": True, "removed": [], "sequence": following, "set": {"generation": 0}},
                "resource generation": {"durable": True, "resources": [{"generation": 0, "removed": [], "set": {}}], "sequence": following},
                "record sequence": {"durable": True, "removed": [], "sequence": 0, "set": {}},
            }
            for name, record in cases.items():
                with self.subTest(case=f"{name} {value}"):
                    body = json.dumps(record, sort_keys=True)
                    body = body.replace('"generation": 0', '"generation": ' + value).replace('"sequence": 0', '"sequence": ' + value)
                    result = self.replay(log_bytes(bodies) + frame(body.encode(), True))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                    self.assertEqual(result.stderr, b"journal log invalid\n")
        # The largest UInt64 is still accepted: every log record is then already checkpointed.
        text = json.dumps({**checkpoint, "journalSequence": 0}).replace('"journalSequence": 0', '"journalSequence": 18446744073709551615')
        (self.directory / "journal.json").write_text(text)
        result = self.replay(log_bytes(bodies))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["journalSequence"], 18446744073709551615)

    def test_a_cjk_profile_name_replays_as_utf8_without_a_warning(self):
        """FIX1-VERIFY N4: raw UTF-8 and \\u escapes above U+00FF decode as UTF-8 and print as UTF-8 octets."""
        bodies = records()
        following = CHECKPOINT_SEQUENCE + len(bodies) + 1
        name = "\u5de5\u4f5c\u7528 VPN \u6771\u4eac"
        for label, body in [("raw", json.dumps({"durable": True, "removed": [], "sequence": following, "set": {"profileName": name}},
                                                ensure_ascii=False, sort_keys=True).encode()),
                            ("escaped", json.dumps({"durable": True, "removed": [], "sequence": following, "set": {"profileName": name}},
                                                   ensure_ascii=True, sort_keys=True).encode())]:
            with self.subTest(case=label):
                result = self.replay(log_bytes(bodies) + frame(body, True))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertIn(name.encode(), result.stdout, "the name is printed as UTF-8 octets")
                self.assertEqual(json.loads(result.stdout.decode("utf-8"))["profileName"], name)
        checkpoint = json.loads((FIXTURE / "journal.json").read_text())
        (self.directory / "journal.json").write_bytes(json.dumps({**checkpoint, "profileName": name}, ensure_ascii=False).encode())
        result = self.replay(log_bytes(bodies))
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(json.loads(result.stdout)["profileName"], name)
        (self.directory / "journal.json").write_bytes(json.dumps(checkpoint).encode()[:-1] + b', "profileName": "\xff\xfe"}')
        result = self.replay(log_bytes(bodies))
        self.assertNotEqual(result.returncode, 0, "invalid UTF-8 is refused")
        self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")

    def test_a_json_string_where_the_daemon_decodes_a_number_is_refused(self):
        """M1-10h VERIFY N6: the daemon's UInt64 decode rejects a JSON string such as "42"; so does the replay."""
        bodies = records()
        following = CHECKPOINT_SEQUENCE + len(bodies) + 1
        checkpoint = json.loads((FIXTURE / "journal.json").read_text())
        for key, value in [("journalSequence", "42"), ("journalSequence", str(CHECKPOINT_SEQUENCE)), ("generation", "42")]:
            with self.subTest(case=f"checkpoint {key} string"):
                (self.directory / "journal.json").write_text(json.dumps({**checkpoint, key: value}))
                result = self.replay(log_bytes(bodies))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                self.assertEqual(result.stderr, b"journal checkpoint invalid\n")
        shutil.copy(FIXTURE / "journal.json", self.directory / "journal.json")
        cases = {
            "record sequence": {"durable": True, "removed": [], "sequence": str(following), "set": {}},
            "generation": {"durable": True, "removed": [], "sequence": following, "set": {"generation": "42"}},
            "resource generation": {"durable": True, "resources": [{"generation": "42", "removed": [], "set": {}}], "sequence": following},
            "entry generation": {"durable": False, "entries": [{"action": "willApply", "generation": "42", "step": "x"}],
                                 "replaceEntries": False, "sequence": following},
        }
        for name, record in cases.items():
            with self.subTest(case=name):
                body = json.dumps(record, sort_keys=True).encode()
                result = self.replay(log_bytes(bodies) + frame(body, record["durable"]))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stdout == b"", "a refused replay prints nothing (values not shown)")
                self.assertEqual(result.stderr, b"journal log invalid\n")
        # The same records with JSON numbers still replay.
        record = {"durable": True, "removed": [], "sequence": following, "set": {}}
        result = self.replay(log_bytes(bodies) + frame(json.dumps(record, sort_keys=True).encode(), True))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_run_7_replay_is_byte_identical_to_its_canonical_utf8_encoding(self):
        result = self.replay(log_bytes(records()))
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = json.dumps(EXPECTED, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        self.assertTrue(hashlib.sha256(result.stdout).digest() == hashlib.sha256(expected).digest(),
                        "the replay differs byte for byte from the expected document (values not shown)")


class RememberTests(unittest.TestCase):
    """The shared remember body, run in zsh (the guest login shell) and bash (the dry-run mock) with fixture providers."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]))
        self.addCleanup(shutil.rmtree, self.directory)
        self.state = self.directory / "state"
        self.stage = self.directory / "stage"
        self.state.mkdir()
        self.stage.mkdir()
        shutil.copy(FIXTURE / "journal.json", self.state / "journal.json")
        (self.state / "journal.log").write_bytes(log_bytes(records()))
        (self.directory / "references").write_text(REFERENCES)

    def run_body(self, shell, body, document_filter="cat", profile=PROFILE, wait=0, provider=None):
        provider = provider or f"journal_document() {{ perl '{REPLAY}' '{self.state}' | {document_filter}; }}"
        prelude = f"""set -eu
stage='{self.stage}'
profile='{profile}'
j='{self.state}/journal.json'
remember_wait={wait}
{provider}
pf_references() {{ cat '{self.directory}/references'; }}
boot_session() {{ printf '66666666-6666-4666-8666-666666666666\\n'; }}
"""
        return subprocess.run([shell, "-c", prelude + body], capture_output=True, check=False)

    def stage_files(self):
        return {path.name: path.read_text() for path in sorted(self.stage.iterdir())}

    def test_the_fixture_reproduces_the_run_6_abort_of_the_pre_m1_12b_reader(self):
        """Fixture characterisation, not a check of the current script: it runs the hard-coded OLD_READER, so it passes
        whatever cutover-rehearsal.sh contains, and proves only that the armed-trial fixture has the run 6 shape."""
        result = self.run_body("/bin/bash", OLD_READER)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"resources.0.addresses.0", result.stderr)

    def test_the_trial_resources_come_from_the_replayed_journal(self):
        for shell in ["/bin/zsh", "/bin/bash"]:
            with self.subTest(shell=shell):
                result = self.run_body(shell, remember_body())
                self.assertEqual(result.returncode, 0, result.stderr)
                same(self, self.stage_files(), {
                    "address": "10.77.0.2\n",
                    "boot": "00000000-0000-4000-8000-000000000102\n",
                    "canary": "192.0.2.1/32 en0 192.168.64.1\n",
                    "dns-key": f"State:/Network/Service/{PROFILE}/DNS\n",
                    "pid": "1088\n",
                    "routes": "192.0.2.1/32 en0\n10.77.0.0/24 utun4\n",
                    "token": EXPECTED["pfToken"] + "\n",
                    "token-source": "journal\n",
                }, "remembered stage")

    def test_without_a_journalled_token_the_sole_pfctl_row_is_used(self):
        strip = "perl -MJSON::PP -e 'my $j = JSON::PP->new; my $d = $j->decode(do { local $/; <STDIN> }); delete @$d{qw(pfToken pfTokenPID pfBootSession)}; print $j->encode($d)'"
        for shell in ["/bin/zsh", "/bin/bash"]:
            with self.subTest(shell=shell):
                result = self.run_body(shell, remember_body(), document_filter=strip)
                self.assertEqual(result.returncode, 0, result.stderr)
                files = self.stage_files()
                # M1-12d VERIFY N4: if the strip regressed the stage would hold the journalled token, so no diff is shown.
                self.assertTrue((files["token-source"], files["token"], files["pid"], files["boot"])
                                == ("references\n", "9002\n", "4243\n", "66666666-6666-4666-8666-666666666666\n"),
                                "the References fallback was not used (values not shown)")
        (self.directory / "references").write_text(REFERENCES + "4244 pfctl 9003 0 days 00:00:01\n")
        self.assertNotEqual(self.run_body("/bin/zsh", remember_body(), document_filter=strip).returncode, 0, "two pfctl rows are ambiguous")
        (self.directory / "references").write_text("TOKENS:\nPID Process Name TOKEN TIMESTAMP\n")
        self.assertNotEqual(self.run_body("/bin/zsh", remember_body(), document_filter=strip).returncode, 0, "no row is no authority")

    def flaky_provider(self, failures):
        """A journal_document that fails its first `failures` replays the way a checkpoint racing the helper's two reads
        does, then replays the fixture; every call is counted in a file because the provider runs in a subshell."""
        calls = self.directory / "calls"
        return (f"journal_document() {{ n=$(($(cat '{calls}' 2>/dev/null || echo 0) + 1)); echo \"$n\" >'{calls}'; "
                f"if test \"$n\" -le {failures}; then echo 'journal log invalid' >&2; return 1; fi; perl '{REPLAY}' '{self.state}'; }}"), calls

    def test_replay_failures_are_retried_until_the_deadline(self):
        for shell in ["/bin/zsh", "/bin/bash"]:
            with self.subTest(shell=shell):
                provider, calls = self.flaky_provider(2)
                calls.unlink(missing_ok=True)
                result = self.run_body(shell, remember_body(), wait=10, provider=provider)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls.read_text(), "3\n", "two failed replays, then success")
                self.assertEqual(self.stage_files()["address"], "10.77.0.2\n")
                self.assertTrue(self.stage_files()["token"] == EXPECTED["pfToken"] + "\n", "token as journalled (values not shown)")

    def test_a_replay_that_never_succeeds_fails_at_the_deadline_with_its_error(self):
        for shell in ["/bin/zsh", "/bin/bash"]:
            with self.subTest(shell=shell):
                provider, calls = self.flaky_provider(1000)
                calls.unlink(missing_ok=True)
                result = self.run_body(shell, remember_body(), wait=2, provider=provider)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"cutover remember: journal replay failed: journal log invalid", result.stderr)
                self.assertGreaterEqual(int(calls.read_text()), 2, "retried before the deadline, not fatal on the first failure")
                self.assertEqual(sorted(p.name for p in self.stage.iterdir()), [], "a refused remember writes nothing")

    def test_a_non_current_neighbour_resource_is_not_remembered(self):
        """M1-12c VERIFY N4, M1-12d VERIFY F2: a durable record adds a generation-9 resource before, then after, the
        generation-10 one; the replay keeps both in record order and the remember body still takes the current
        generation's address and routes, so neither a take-first nor a take-last reader passes."""
        current = EXPECTED["resources"][0]
        neighbour = {**current, "generation": 9, "addresses": ["10.77.0.9/24"],
                     "routes": [{"destination": "10.77.9.0", "interfaceName": "utun9", "prefixLength": 24}]}
        edits = {9: {"generation": 9, "removed": [], "set": neighbour}, 10: {"generation": 10, "removed": [], "set": {}}}
        resources = {9: neighbour, 10: current}
        for order in [[9, 10], [10, 9]]:
            record = {"durable": True, "removed": [], "sequence": EXPECTED["journalSequence"] + 1,
                      "resources": [edits[generation] for generation in order]}
            body = json.dumps(record, sort_keys=True).encode()
            (self.state / "journal.log").write_bytes(log_bytes(records()) + frame(body, True))
            replay = subprocess.run(["perl", str(REPLAY), str(self.state)], capture_output=True, check=False)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            document = json.loads(replay.stdout)
            self.assertEqual((document["generation"], [r["generation"] for r in document["resources"]]), (10, order))
            same(self, document["resources"], [resources[generation] for generation in order], "replayed resources")
            for shell in ["/bin/zsh", "/bin/bash"]:
                with self.subTest(order=order, shell=shell):
                    for path in self.stage.iterdir():
                        path.unlink()
                    result = self.run_body(shell, remember_body())
                    self.assertEqual(result.returncode, 0, result.stderr)
                    files = self.stage_files()
                    self.assertEqual((files["address"], files["routes"]), ("10.77.0.2\n", "192.0.2.1/32 en0\n10.77.0.0/24 utun4\n"))

    def test_a_checkpoint_without_the_log_or_another_trial_is_refused(self):
        (self.state / "journal.log").unlink()
        result = self.run_body("/bin/zsh", remember_body())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"no tunnel address", result.stderr)
        (self.state / "journal.log").write_bytes(log_bytes(records()))
        self.assertNotEqual(self.run_body("/bin/zsh", remember_body(), profile="11111111-1111-1111-1111-111111111111").returncode, 0)
        self.assertEqual(sorted(p.name for p in self.stage.iterdir()), [], "a refused remember writes nothing")


class DryRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = subprocess.run(["bash", str(SCRIPT), "--dry-run"], capture_output=True, check=False, cwd=ROOT)

    def test_the_dry_run_exercises_remember_against_the_fixture(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr[-2000:])
        self.assertIn(b"armed-trial journal replayed, References fallback; 17 corrupt fixtures rejected", self.result.stdout)
        self.assertIn(b"# cutover:remember", self.result.stderr)

    def test_the_live_remember_command_carries_the_shared_body_and_the_guest_providers(self):
        """The mock sources the shared body file whatever remember_resources sends, so the command it logged (printf %q,
        decoded by bash itself) must carry that body, the stage and profile it sets and the three guest providers, and the
        helper must be staged before the first remember: a regression in the live wrapper alone cannot pass the dry run."""
        self.assertEqual(self.result.returncode, 0, self.result.stderr[-2000:])
        logged = self.result.stderr.decode().splitlines()
        lines = [line for line in logged if line.startswith("dry-run: ssh ") and "cutover:remember" in line]
        self.assertGreaterEqual(len(lines), 5)
        staged = [n for n, line in enumerate(logged)
                  if re.match(r"dry-run: scp .* \S+/journal-replay\.pl \S+@\S+:/Users/[^/]+/lab/cutover/journal-replay\.pl$", line)]
        self.assertTrue(staged, "journal-replay.pl is staged into the guest")
        self.assertLess(staged[0], logged.index(lines[0]), "the helper is staged before the first remember")
        decode = 'eval "set -- ${1#dry-run: }"; printf "%s" "${!#}"'
        body = remember_body()
        providers = [
            r"^journal_document\(\) \{ sudo -n /usr/bin/perl '/Users/[^/']+/lab/cutover/journal-replay\.pl' '/Library/Application Support/WGEX'; \}$",
            r"^pf_references\(\) \{ sudo -n /sbin/pfctl -s References 2>/dev/null; \}$",
            r"^boot_session\(\) \{ /usr/sbin/sysctl -n kern\.bootsessionuuid; \}$",
            r"^remember_wait=60$",
            r"^stage='/Users/[^/']+/lab/cutover'$",
            rf"^profile='{PROFILE}'$",
        ]
        for line in lines:
            decoded = subprocess.run(["bash", "-c", decode, "decode", line], capture_output=True, check=True, text=True).stdout
            self.assertTrue(decoded.endswith("\n# cutover:remember"), decoded[-200:])
            start = decoded.find(body)
            self.assertGreater(start, 0, "the shared remember body is sent verbatim")
            for pattern in providers:
                match = re.search(pattern, decoded, re.M)
                self.assertIsNotNone(match, pattern)
                self.assertLess(match.start(), start, f"{pattern} is defined before the body runs")


if __name__ == "__main__":
    unittest.main()
