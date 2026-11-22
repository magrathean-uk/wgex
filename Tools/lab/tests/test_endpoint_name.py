# SPDX-License-Identifier: MIT
"""Fresh-name failure and VPS DNS-only row verdicts, offline: no guest or network access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_live_replay as replay

LIVE, ROOT = replay.LIVE, replay.ROOT


def evidence(lookup=False):
    value = dict(freshName=True, noLastGood=True, faultPackets=1, exitCode=8, error="underlayResolverNoAnswer", elapsedSeconds=8.5,
                 before=dict(phase="idle", protection="unprotected", policyEnforcing=False),
                 after=dict(phase="idle", protection="unprotected", policyEnforcing=False, activeProfileID=None,
                            operationInFlight=False, cutover=dict(state="rolledBack", reason="startFailed"), cutoverRollbackFailures=[]))
    if lookup:
        value.update(lookupHost="cdn.example.net", addresses=["203.0.113.75"], connectingBeforeLookup=True, connectingAfterLookup=True)
    return value


class EndpointNameTests(unittest.TestCase):
    def test_the_session_dispatches_each_row_and_publishes_its_checks(self):
        rows = json.loads((ROOT / "Tools/lab/rows.json").read_bytes())["rows"]
        for row, lookup in (("M04-T13-NAME-FAIL", False), ("M04-T13-VPS-LOOKUP", True)):
            entry = rows[row]
            self.assertFalse(entry["connect"])
            self.assertEqual(entry["profile"], "full4-name")
            session = LIVE.Session.__new__(LIVE.Session)
            session.row_observation, session.profile_ids = {}, {"full4-name": "fixture-profile"}
            calls = []
            def step(*args, **kwargs):
                calls.append((args, kwargs))
                return json.dumps(evidence(lookup)).encode()
            session.endpoint_name_step = step
            checks = session.endpoint_name_row(entry["action"], entry["profile"])
            self.assertTrue(all(c["met"] for c in checks), checks)
            self.assertEqual(calls[0][0], (entry["action"], "fixture-profile"))
            self.assertEqual(session.row_observation["endpointName"], evidence(lookup))

    def test_each_missing_or_bad_observation_fails_its_check(self):
        cases = [("freshName", False, "freshNameWithoutCachedAnswer"), ("noLastGood", False, "freshNameWithoutCachedAnswer"),
                 ("faultPackets", 0, "resolverUnreachableInGuest"), ("exitCode", 1, "namedFailure"),
                 ("error", "daemonUnavailable", "namedFailure"), ("elapsedSeconds", 15.01, "automaticRollbackWithin15Seconds"),
                 ("elapsedSeconds", -1, "automaticRollbackWithin15Seconds"),
                 ("lookupHost", "other.test", "vpsDNSOnlyUnderConnectingPolicy"),
                 ("addresses", ["192.0.2.1"], "vpsDNSOnlyUnderConnectingPolicy"),
                 ("connectingBeforeLookup", False, "vpsDNSOnlyUnderConnectingPolicy"),
                 ("connectingAfterLookup", False, "vpsDNSOnlyUnderConnectingPolicy")]
        for key, bad, name in cases:
            for missing in (False, True):
                value = evidence(True)
                if missing:
                    del value[key]
                else:
                    value[key] = bad
                check = next(c for c in LIVE.endpoint_name_checks("endpoint-name-lookup", value) if c["name"] == name)
                self.assertFalse(check["met"], (key, missing))
        for key, bad in (("protection", "blocked"), ("phase", "failed"), ("policyEnforcing", True),
                         ("activeProfileID", "still-active"), ("operationInFlight", True), ("cutoverRollbackFailures", ["pf"])):
            value = evidence()
            value["after"][key] = bad
            checks = LIVE.endpoint_name_checks("endpoint-name-fail", value)
            self.assertFalse(next(c["met"] for c in checks if c["name"] == "priorProtectionRestoredWithoutAbort"), key)
        value = evidence()
        value["after"]["cutover"]["reason"] = "aborted"
        self.assertFalse(all(c["met"] for c in LIVE.endpoint_name_checks("endpoint-name-fail", value)))
        self.assertFalse(any(c["met"] for c in LIVE.endpoint_name_checks("endpoint-name-lookup", {})))
        print("negative cases: FAIL namedFailure (daemonUnavailable); FAIL automaticRollbackWithin15Seconds (15.01 s); "
              "FAIL freshNameWithoutCachedAnswer (last-good present); FAIL resolverUnreachableInGuest (0 fault packets); "
              "FAIL priorProtectionRestoredWithoutAbort (blocked); FAIL vpsDNSOnlyUnderConnectingPolicy (wrong answer/policy)")

    def test_guest_failure_action_measures_the_request_and_restores_its_own_fault(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
            stage = Path(directory)
            (stage / "guard.sh").write_text("guest_guard() { :; }\n")
            (stage / "journal-replay.pl").write_text("print '{\"lastGoodAddresses\":{}}';\n")
            (stage / "asu.sh").write_text('exec "$@"\n')
            (stage / "endpoint-name").write_text("never-1234.invalid\n")
            cli = stage / "cli"
            cli.write_text("""#!/bin/bash
if [[ "$1" == cutover ]]; then
  touch "$NAME_TEST_DIR/started"
  printf '{"error":"underlayResolverNoAnswer"}\\n'
  exit 8
fi
if [[ -e "$NAME_TEST_DIR/started" ]]; then
  printf '%s\\n' '{"phase":"idle","protection":"unprotected","policyEnforcing":false,"activeProfileID":null,"operationInFlight":false,"cutover":{"state":"rolledBack","reason":"startFailed"},"cutoverRollbackFailures":[]}'
else
  printf '%s\\n' '{"phase":"idle","protection":"unprotected","policyEnforcing":false}'
fi
""")
            (stage / "sudo").write_text('#!/bin/bash\nshift\nexec "$@"\n')
            (stage / "pfctl").write_text("""#!/bin/bash
printf '%s\\n' "$*" >> "$NAME_TEST_DIR/pf-log"
case "$*" in
  -E) printf 'Token : 123\\n' ;;
  *-vsr) printf '[ Evaluations: 1 Packets: 1 Bytes: 40 States: 0 ]\\n' ;;
  *'-f -') cat >/dev/null ;;
esac
""")
            for name in ("cli", "sudo", "pfctl"):
                (stage / name).chmod(0o700)
            script = (ROOT / "Tools/lab/tart/guest/endpoint-name.sh").read_text()
            (stage / "endpoint-name.sh").write_text(script.replace("cli=/Applications/WGEX.app/Contents/Helpers/wgex", "cli=" + str(cli)))
            env = dict(os.environ, PATH=str(stage) + ":" + os.environ["PATH"], NAME_TEST_DIR=str(stage))
            run = subprocess.run(["bash", str(stage / "endpoint-name.sh"), "endpoint-name-fail",
                                  "00000000-0000-4000-8000-000000000101"], env=env, capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            value = json.loads(run.stdout)
            self.assertTrue(all(c["met"] for c in LIVE.endpoint_name_checks("endpoint-name-fail", value)), value)
            self.assertIn("-X 123", (stage / "pf-log").read_text())
            self.assertFalse(list(stage.glob("name-check.*")))

    def test_guest_fault_is_guarded_fresh_bounded_and_never_starts_a_vps_tunnel(self):
        script = (ROOT / "Tools/lab/tart/guest/endpoint-name.sh").read_text()
        self.assertLess(script.index("guest_guard"), script.index("pfctl"))
        self.assertIn('never-$(uuidgen', script)
        self.assertIn(".invalid", script)
        self.assertIn('lastGoodAddresses', script)
        self.assertIn('alarm 14', script)
        self.assertIn('alarm 1', script)
        self.assertNotIn('cutover abort', script)
        self.assertIn('/usr/bin/dig "@$resolver" cdn.example.net A', script)
        self.assertIn('cmp -s "$work/rules" "$work/after-rules"', script)
        self.assertIn('trap cleanup EXIT', script)
        self.assertIn('block drop out quick to 203.0.113.75', script)
        self.assertIn('bash "$stage/asu.sh" perl -e', script)
