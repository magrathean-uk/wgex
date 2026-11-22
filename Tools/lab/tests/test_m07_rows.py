# SPDX-License-Identifier: MIT
"""M07-T08b: the M07 row driver's pure parts (dump and menu parsing, the live-menu checks, verdict outcome and scrubbing,
the synthetic tunnel script) and its row catalogue. Never a VM, never a guest."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("m07_rows", ROOT / "Tools/lab/m07/m07-rows.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
KEY = "A" * 43 + "="
DUMP = "\n".join([
    "AXWindow | name=wgex-lab-default | value= | desc= | id= | pos=0,25 size=1000x700",
    "AXButton | name=missing value | value=missing value | desc=Activate | id=wgex.main.action | pos=700,60 size=90x24 en=true",
    "AXGroup | name=missing value | value=missing value | desc=Public key | id=wgex.editor.publicKey | pos=100,200 size=500x24 en=true",
    f"AXStaticText | name={KEY} | value={KEY} | desc=text | id= | pos=300,204 size=280x16 en=true",
    "AXCheckBox | name=Allow local network | value=1 | desc=Allow local network | id=wgex.protection.allowLocalNetwork | pos=10,10 size=30x16 en=true",
    "AXRow | name=missing value | value=missing value | desc=wgex-lab-default, Inactive | id=wgex.main.tunnel.AAAA | pos=0,80 size=220x24 en=true",
    "AXRow | name=missing value | value=missing value | desc=m07-zip-a-a1, Inactive | id=wgex.main.tunnel.BBBB | pos=0,104 size=220x24 en=true",
    "ax-walk: elements=7 truncated=0 errors=0",
])


def menu(*titles, ticked=()):
    lines = [f"item={t}\tmark={'✓' if t in ticked else 'missing value'}\tenabled=true" for t in titles]
    return "\n".join(lines + ["menu=read"])


LIVE = ("Status: Active", "", "wgex-lab-default", "Interface: utun4", "Address: 10.77.0.2", "Handshake: 3 s ago")


class DumpTests(unittest.TestCase):
    def test_elements_and_lookup(self):
        self.assertEqual([item["id"] for item in M.by_id(DUMP, "wgex.main.tunnel.", prefix=True)],
                         ["wgex.main.tunnel.AAAA", "wgex.main.tunnel.BBBB"])
        self.assertEqual(M.text_of(M.by_id(DUMP, "wgex.main.action")[0]), "Activate")
        self.assertEqual(M.text_of(M.by_id(DUMP, "wgex.protection.allowLocalNetwork")[0]), "1")
        self.assertEqual(M.centre(M.by_id(DUMP, "wgex.main.action")[0]["frame"]), (745, 72))
        self.assertEqual(M.window_name(DUMP), "wgex-lab-default")

    def test_public_key_is_only_a_digest(self):
        digest = M.public_key_digest(DUMP)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotIn(KEY, digest)
        self.assertIsNone(M.public_key_digest(DUMP.replace("id=wgex.editor.publicKey", "id=")))

    def test_public_key_frame_from_ax_find(self):
        # Live run 3: a row whose role gui dump does not print has no dump line; ax-find's frame stands in for it.
        dump = DUMP.replace("id=wgex.editor.publicKey", "id=")
        self.assertIsNone(M.public_key_digest(dump))
        self.assertEqual(M.public_key_digest(dump, (100, 200, 500, 24)), M.public_key_digest(DUMP))
        self.assertIsNone(M.public_key_digest(dump, (0, 0, 10, 10)))


class FindTests(unittest.TestCase):
    def test_found_parses_any_role(self):
        item = M.found("ax-find=found\trole=AXUnknown\tvalue=Running\tlabel=Background service\ttitle=\tenabled=true"
                       "\tframe=20,300,480,36\nax-walk: elements=55 truncated=0 errors=0")
        self.assertEqual((item["role"], item["value"], item["enabled"], item["frame"], item["contains"]),
                         ("AXUnknown", "Running", "true", (20, 300, 480, 36), None))
        self.assertEqual(M.texts(item), ["Running", "Background service"])
        self.assertEqual(M.centre(item["frame"]), (260, 318))

    def test_found_contains_and_omitted_value(self):
        item = M.found("ax-find=found\trole=AXScrollArea\tvalue=<omitted>\tlabel=Edit as Text\ttitle=\tenabled=\tframe=1,2,3,4"
                       "\tcontains=yes\nax-walk: elements=9 truncated=0 errors=0")
        self.assertTrue(item["contains"])
        self.assertEqual(M.texts(item), ["Edit as Text"])
        self.assertFalse(M.found(item_line := "ax-find=found\trole=AXButton\tcontains=no")["contains"])
        self.assertIsNone(M.found(item_line.replace("found", "missing")))

    def test_found_rejects_missing_and_noise(self):
        self.assertIsNone(M.found("ax-find=missing\nax-walk: elements=55 truncated=0 errors=0"))
        self.assertIsNone(M.found(""))
        self.assertIsNone(M.found(None))
        self.assertIsNone(M.found("ax-find=found\trole=AXButton\tframe=1,2,x,4")["frame"])
        self.assertEqual(M.texts(None), [])
        self.assertEqual(M.texts(dict(value="missing value", title="Activate", label="Activate")), ["Activate"])

    def test_finder_never_prints_secret_values(self):
        script = (ROOT / "Tools/lab/m07/ax-find.applescript").read_text()
        for marker in ('r is "AXTextArea"', 'sr is "AXSecureTextField"', 'targetIdent contains "rivateKey"',
                       'targetIdent contains "configurationText"', 'if secret or containsMode then set v to "<omitted>"',
                       'set t to "<omitted>"', 'if not (secret or containsMode) then set t to my textOf(e, 0)'):
            self.assertIn(marker, script)

    def test_text_is_read_in_one_place(self):
        # Live run 4: a SwiftUI button answers no AXTitle or AXDescription; ax-find's text carries what it can find.
        item = M.found("ax-find=found\trole=AXButton\tvalue=\tlabel=\ttitle=\tenabled=true\tframe=905,136,73,24"
                       "\ttext=Activate\tattrs=AXRole,AXIdentifier,AXEnabled\nax-walk: elements=9 truncated=0 errors=0")
        self.assertEqual((M.texts(item), item["attrs"]), (["Activate"], "AXRole,AXIdentifier,AXEnabled"))
        self.assertEqual(M.texts(dict(value="Running", title="", label="Background service", text="Running")),
                         ["Running", "Background service"])
        bare = M.found("ax-find=found\trole=AXButton\tvalue=\tlabel=\ttitle=\tenabled=true\tframe=1,2,3,4\ttext=")
        self.assertEqual(M.texts(bare), [])

    def test_label_checks_fall_back_to_the_tied_state(self):
        read = M.label_check("activateOffered", "Activate", "Activate", False, "daemon unprotected", "offers Activate")
        self.assertTrue(read["met"])
        self.assertIn("'Activate'", read["summary"])
        self.assertFalse(M.label_check("activateOffered", "Deactivate", "Activate", True, "x", "offers Activate")["met"])
        unexposed = M.label_check("activateOffered", "", "Activate", True, "daemon unprotected True", "offers Activate")
        self.assertTrue(unexposed["met"])
        self.assertIn("label not exposed", unexposed["summary"])
        self.assertTrue(M.label_check("n", "Add All -> Add 2", lambda t: t.endswith("2"), False, "x", "y")["met"])

    def test_text_only_checks_become_gaps_when_unreadable(self):
        item, gap = M.text_check("reviewServer", "192.0.2.1:51820 10.77.0.2/32", lambda t: "10.77." in t, "shows server")
        self.assertTrue(item["met"])
        self.assertIsNone(gap)
        item, gap = M.text_check("reviewServer", "", lambda t: True, "shows server")
        self.assertIsNone(item)
        self.assertIn("not exposed to accessibility", gap)

    def test_console_gets_the_job_login_file(self):
        calls = []

        class Console:
            popen = staticmethod(lambda argv, **kwargs: calls.append((argv, kwargs)))
        console = M.with_login_file(Console(), "/tmp/job/wgex-image-login-x")
        console.popen(["python3", "console.py", "approve"], cwd="/r")
        self.assertEqual(calls, [(["python3", "console.py", "approve", "--login-file", "/tmp/job/wgex-image-login-x"], {"cwd": "/r"})])
        self.assertIsNone(M.with_login_file(None, "/x"))
        plain = Console()
        self.assertIs(M.with_login_file(plain, None).popen, Console.popen)


class MenuTests(unittest.TestCase):
    def test_read_needs_its_end_marker(self):
        self.assertIsNone(M.menu_items("item=Status: Active\tmark=\tenabled=true"))
        self.assertEqual(M.menu_items(menu("wgex-lab-default", ticked=("wgex-lab-default",))), [("wgex-lab-default", True, True)])

    def test_live_checks(self):
        first = M.menu_items(menu(*LIVE, "Download: 1.2 kB/s (3.4 kB)", "Upload: 900 B/s (2 kB)", "Kill Switch: On",
                                  ticked=("wgex-lab-default",)))
        second = M.menu_items(menu(*LIVE, "Download: 1.5 kB/s (9.8 kB)", "Upload: 800 B/s (5 kB)", "Kill Switch: On",
                                   ticked=("wgex-lab-default",)))
        checks = {item["name"]: item["met"] for item in M.live_checks(first, second, "wgex-lab-default")}
        self.assertTrue(all(checks.values()), checks)
        frozen = M.live_checks(first, first, "wgex-lab-default")
        self.assertFalse({item["name"]: item["met"] for item in frozen}["ratesLive"])
        unticked = M.menu_items(menu(*LIVE, "Download: Unavailable (Unavailable)", "Upload: Unavailable (Unavailable)"))
        checks = {item["name"]: item["met"] for item in M.live_checks(unticked, unticked, "wgex-lab-default")}
        self.assertFalse(checks["tunnelTicked"] or checks["rateLines"] or checks["killSwitchLine"])


class CandidateTests(unittest.TestCase):
    """M07-T15: the missing-control error lists the ids the window offered next to the one searched for."""
    def test_exact_count_and_near_ids(self):
        spec = importlib.util.spec_from_file_location("m07_live", ROOT / "Tools/lab/verdict-live.py")
        live = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(live)
        dump = DUMP + "\nAXButton | name=Edit as Text | desc= | id=wgex.editor.editAsText | pos=1,1 size=2x2 en=true"
        self.assertEqual(live.control_candidates(dump, "wgex.editor.editAsForm"), (0, ["wgex.editor.editAsText", "wgex.editor.publicKey"]))
        self.assertEqual(live.control_candidates(dump, "wgex.main.action")[0], 1)
        self.assertEqual(live.control_candidates("", "wgex.x.y"), (0, []))


class OutcomeTests(unittest.TestCase):
    def test_outcomes(self):
        ok, bad = M.check("a", True, "x"), M.check("b", False, "y")
        self.assertEqual(M.outcome([ok]), ("passed", None))
        self.assertEqual(M.outcome([ok, bad]), ("failed", "b: y"))
        self.assertEqual(M.outcome([]), ("failed", "no checks recorded"))
        self.assertEqual(M.outcome([ok], M.Precondition("gone"))[0], "notMeasured")
        self.assertEqual(M.outcome([ok], M.ProductFailure("sheet missing")), ("failed", "sheet missing"))
        self.assertEqual(M.outcome([ok], ValueError("missing or ambiguous accessible control"))[0], "driverFault")
        self.assertEqual(set(M.EXIT), {"passed", "failed", "driverFault", "notMeasured"})

    def test_written_verdict_is_scrubbed_and_never_accepted_without_a_pass(self):
        record = M.verdict("M07-SETUP", 1, [M.check("a", False, KEY)], None, dict(sourceCommit=None), {}, {})
        with tempfile.TemporaryDirectory() as directory:
            M.write(Path(directory) / "M07-SETUP", record, [])
            text = (Path(directory) / "M07-SETUP/verdict.json").read_text()
            self.assertTrue((Path(directory) / "M07-SETUP/verdict-1.json").exists())
        self.assertNotIn(KEY, text)
        written = json.loads(text)
        self.assertEqual((written["result"], written["liveAcceptance"], written["expectationsMet"]), ("failed", False, False))
        passed = M.verdict("M07-SETUP", 2, [M.check("a", True, "x")], None, {}, {}, {})
        with tempfile.TemporaryDirectory() as directory:
            M.write(Path(directory) / "M07-SETUP", passed, ["Provenance: guestOS.buildVersion missing"])
        self.assertFalse(passed["liveAcceptance"])


class CatalogueTests(unittest.TestCase):

    def test_guest_helpers_exist(self):
        for folder, name in M.GUEST_HELPERS:
            self.assertTrue((ROOT / "Tools/lab" / folder / name).is_file(), name)

    def test_synthetic_script_keeps_keys_in_the_guest(self):
        script = M.synthetic_conf_script("/Users/admin/lab/m07", ["m07-zip-a-a1", "m07-zip-b-a1"], 10)
        self.assertIn("umask 077", script)
        self.assertEqual(script.count("head -c 32 /dev/urandom | base64"), 4)
        self.assertIn("Endpoint = 192.0.2.11:51820", script)
        self.assertIn("Address = 10.211.0.2/32", script)
        self.assertIsNone(re.search(r"\becho\b|\bcat\b", script))

    def test_added_tunnel_names_resolve_through_profile_id(self):
        # Live run 5: profile-id.sh refused m07-<base> names, so every tunnel a row added read as not stored.
        script = (ROOT / "Tools/lab/tart/guest/profile-id.sh").read_text()
        pattern = re.search(r'"\$expected" =~ (\^\S+\$) \]\]', script).group(1)
        rows = M.Rows.__new__(M.Rows)
        for attempt in (1, 2):
            rows.attempt = attempt
            for base in ("empty", "text", "zip-a", "zip-b", "zip-c"):
                self.assertRegex(rows.name(base), pattern)
        self.assertEqual(M.PROFILE_NAME.pattern, pattern.strip("^$"))
        with self.assertRaises(ValueError):
            M.tunnel_name("Bad Name", 1)

class FocusTests(unittest.TestCase):
    # M07-T16: focus is read through AXFocusedUIElement; a text editor's identifier sits on its scroll area (an ancestor).
    def test_focus_reading_finds_the_identifier_on_an_ancestor(self):
        reading = M.focus_reading("focus=found\trole=AXTextArea\tid0=\tid1=wgex.editor.configurationText\tid2=missing value")
        self.assertEqual(reading, dict(role="AXTextArea", ids=["wgex.editor.configurationText"]))
        self.assertTrue(M.focus_on(reading, "wgex.editor.configurationText"))
        self.assertFalse(M.focus_on(reading, "wgex.editor.field.name"))

    def test_nothing_focused_is_none(self):
        self.assertIsNone(M.focus_reading("focus=none"))
        self.assertIsNone(M.focus_reading(""))
        self.assertFalse(M.focus_on(None, "wgex.editor.field.name"))
        self.assertEqual(M.describe_focus(None), "nothing")

    def test_focus_mode_targets_the_text_area_of_a_scroll_area(self):
        script = (ROOT / "Tools/lab/m07/ax-find.applescript").read_text()
        for marker in ('item 4 of argv is "focus"', '(first UI element of e whose role is "AXTextArea")',
                       'set value of attribute "AXFocused" of target to true'):
            self.assertIn(marker, script)


if __name__ == "__main__":
    unittest.main()
