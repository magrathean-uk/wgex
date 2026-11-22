# SPDX-License-Identifier: MIT
"""M04-T01: the sitting pack's order check, a pass and each misorder. Pure text; no VM, network or host operation."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "Tools/lab/check-sitting.py"
spec = importlib.util.spec_from_file_location("check_sitting", SCRIPT)
CS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CS)

START = 'chk cutover-start --profile "$PROFILE" --confirm-within 10m'
CONFIRM = "chk cutover-confirm"
ORDER = ["E1", "E2", "E3", "E4", "C1", "C2", "S1", "S2", "S3", "C3", "S4", "S5", "S6", "S7", "S8"]
S123 = 'chk leakwatch --vps4 "$VPS4"; chk s123 --vps4 "$VPS4" --vps6 "$VPS6" --dns "$DNSIP" --phys "$PHYS"'
AFTER_CONFIRM = ("### After cutover confirm\n\nDisarm first.\n\n```sh\nchk disarm --profile \"$PROFILE\"\n```\n\n"
                 "Then abort.\n\n```sh\nchk abort\n```\n")
DISARM_FAILED = "### Disarm not verified\n\nBoot the daemon out.\n\n```sh\nsudo -v\nchk bootout\n```\n"
HEAD = "## Rollback\n\nAbort first.\n\n" + AFTER_CONFIRM + "\n" + DISARM_FAILED
INCLUDE = "Turn Wi-Fi off from the menu bar, wait ten seconds, and turn Wi-Fi back on.\n"
EXCLUDE = "Turn Wi-Fi off, wait ten seconds, turn it back on, and click nothing.\n"


def fenced(*commands):
    return "```sh\n" + "\n".join(commands) + "\n```\n"


def two_changes(name, first=S123, second=S123):
    return ("### %s Title\n\nFirst change.\n\nCommand:\n\n%s\nExpected: pass\n\nSecond change.\n\nCommand:\n\n%s\n"
            "Expected: pass\n" % (name, fenced(first), fenced(second)))


def s6(include=INCLUDE, exclude=EXCLUDE, until="chk phasewatch --until active", hold="chk phasewatch --hold idle",
       wait="chk phasewatch --until idle"):
    return ("### S6 Title\n\nSetup.\n\nCommand:\n\n" + fenced("chk arm --profile \"$PROFILE\"") + "\nExpected: armed\n\n"
            + include + "\nCommand:\n\n" + fenced(until, "chk s123") + "\nExpected: active\n\n"
            + "Switch to Except these networks and Save.\n\nCommand:\n\n" + fenced(wait) + "\nExpected: idle\n\n"
            + exclude + "\nCommand:\n\n" + fenced(hold) + "\nExpected: idle\n")


ARMED = ("chk status cutover.state protection phase operationInFlight --expect cutover.state=armed "
         "--expect protection=protected --expect phase=active --expect operationInFlight=false")


SECTIONS = {"S4": two_changes("S4"), "S5": two_changes("S5"), "S6": s6()}


def section(name, command=None, expected=None, labels=True):
    lines = ["### %s Title of %s" % (name, name), ""]
    if labels:
        lines += ["Command:", "```sh", command or "true", "```", "", "Expected: " + (expected or "it works"), ""]
    return "\n".join(lines) + "\n"


def pack(order=ORDER, head=HEAD, override=None):
    """The minimal well-ordered pack; `override` maps a heading name to replacement section text."""
    parts = [head, "\n## Prerequisites\n\nNothing.\n"]
    for name in order:
        if override and name in override:
            parts.append(override[name])
            continue
        if name in SECTIONS:
            parts.append(SECTIONS[name])
            continue
        command = {"C2": START + "\n" + ARMED, "C3": CONFIRM}.get(name)
        parts.append(section(name, command))
    return "".join(parts)


class OrderCheck(unittest.TestCase):
    def problems(self, text):
        return CS.check(text)

    def assertFails(self, text, needle):
        found = self.problems(text)
        self.assertTrue(found, "expected a failure mentioning %r" % needle)
        self.assertTrue(any(needle in item for item in found), "%r not in %r" % (needle, found))

    def test_well_ordered_pack_passes(self):
        self.assertEqual(self.problems(pack()), [])

    def test_first_h2_must_be_rollback(self):
        self.assertFails(pack(head="## Prerequisites\n\nFirst.\n"), "first `## ` heading must be `## Rollback`")
        no_h2 = pack(head="# Title\n\nIntro.\n").replace("\n## Prerequisites\n\nNothing.\n", "")
        self.assertFails(no_h2, "found None")
        self.assertFails(pack(head="## Rollbacks\n"), "found 'Rollbacks'")

    def test_a_fenced_rollback_heading_does_not_count(self):
        text = "```\n## Rollback\n```\n" + pack(head="## Prerequisites\n")
        self.assertFails(text, "first `## `")

    def test_each_e_check_must_precede_c1(self):
        for late in ("E1", "E2", "E3", "E4"):
            order = [n for n in ORDER if n != late]
            order.insert(order.index("C1") + 1, late)
            self.assertFails(pack(order=order), "must precede")

    def test_e_checks_keep_their_own_order(self):
        order = list(ORDER)
        order[0], order[1] = order[1], order[0]
        self.assertFails(pack(order=order), "E1 must precede E2")

    def test_c1_must_precede_the_start_line(self):
        start_in_e4 = {"E4": section("E4", START), "C2": section("C2", "true")}
        self.assertFails(pack(override=start_in_e4), "C1 must precede the `cutover start` line")

    def test_start_line_must_precede_s1_to_s3(self):
        for name in ("S1", "S2", "S3"):
            order = [n for n in ORDER if n != name]
            order.insert(order.index("C2"), name)
            self.assertFails(pack(order=order), "%s must follow the `cutover start` line" % name)

    def test_s1_to_s3_must_precede_confirm(self):
        for name in ("S1", "S2", "S3"):
            order = [n for n in ORDER if n != name]
            order.insert(order.index("C3") + 1, name)
            self.assertFails(pack(order=order), "%s must precede the `cutover confirm` line" % name)

    def test_s4_to_s8_must_follow_confirm(self):
        for name in ("S4", "S5", "S6", "S7", "S8"):
            order = [n for n in ORDER if n != name]
            order.insert(order.index("C3"), name)
            self.assertFails(pack(order=order), "%s must follow the `cutover confirm` line" % name)

    def test_confirm_before_start_fails(self):
        swapped = {"C2": section("C2", CONFIRM), "C3": section("C3", START)}
        self.assertFails(pack(override=swapped), "start` line must precede the `cutover confirm")

    def test_start_and_confirm_lines_must_each_appear_once(self):
        self.assertFails(pack(override={"C2": section("C2", "true")}), "exactly one `chk cutover-start`")
        self.assertFails(pack(override={"C3": section("C3", "true")}), "exactly one `chk cutover-confirm`")
        twice = {"C2": section("C2", START + "\n" + START)}
        self.assertFails(pack(override=twice), "found 2")

    def test_prose_mentions_of_start_and_confirm_do_not_count(self):
        text = pack(head=HEAD + "\nBefore `cutover start` and after `cutover confirm` run abort.\n"
                    "chk cutover-start in prose\nchk cutover-confirm in prose\n")
        self.assertEqual(self.problems(text), [])

    def test_raw_cli_start_and_confirm_do_not_count(self):
        # Round 5 item 6: C2 and C3 run through the helper, which fails on a non-zero exit or an error reply.
        raw = {"C2": section("C2", '"$cli" cutover start "$PROFILE" --confirm-within 10m; echo "start exit=$?"'),
               "C3": section("C3", '"$cli" cutover confirm; echo "confirm exit=$?"')}
        found = self.problems(pack(override=raw))
        self.assertIn("expected exactly one `chk cutover-start` command line, found 0", found)
        self.assertIn("expected exactly one `chk cutover-confirm` command line, found 0", found)
        self.assertFails(pack(override={"C2": section("C2", "chk cutover-started")}), "found 0")

    def test_missing_and_duplicate_headings_fail(self):
        for name in ORDER:
            self.assertFails(pack(order=[n for n in ORDER if n != name]), "missing heading %s" % name if name not in ("C2", "C3") else "exactly one")
        self.assertFails(pack(order=ORDER + ["S8"]), "S8 heading appears more than once")

    def test_every_heading_needs_command_then_expected(self):
        for name in ORDER:
            no_labels = {name: section(name, labels=False)}
            if name in ("C2", "C3"):
                no_labels[name] = "### %s Title\n\n```sh\n%s\n```\n" % (name, START if name == "C2" else CONFIRM)
            self.assertFails(pack(override=no_labels), "%s has no `Command:` line" % name)
        only_command = {"S5": "### S5 Title\n\nCommand: true\n"}
        self.assertFails(pack(override=only_command), "S5 has no `Expected:` line")
        only_expected = {"E2": "### E2 Title\n\nExpected: fine\n"}
        self.assertFails(pack(override=only_expected), "E2 has no `Command:` line")

    def test_expected_before_command_fails(self):
        swapped = {"E3": "### E3 Title\n\nExpected: fine\n\nCommand: true\n"}
        self.assertFails(pack(override=swapped), "E3 has `Expected:` before `Command:`")

    def test_labels_need_content(self):
        empty_command = {"S1": "### S1 Title\n\nCommand:\n\nExpected: fine\n"}
        self.assertFails(pack(override=empty_command), "S1 has an empty `Command:`")
        empty_expected = {"S1": "### S1 Title\n\nCommand: true\n\nExpected:\n"}
        self.assertFails(pack(override=empty_expected), "S1 has an empty `Expected:`")
        empty_fence = {"S1": "### S1 Title\n\nCommand:\n```sh\n```\nExpected: fine\n"}
        self.assertFails(pack(override=empty_fence), "S1 has an empty `Command:`")

    def test_labels_of_the_next_heading_do_not_count(self):
        # S1 has none of its own; the labels below belong to S2.
        text = pack(override={"S1": "### S1 Title\n\nprose only\n"})
        self.assertFails(text, "S1 has no `Command:` line")

    def test_a_label_inside_a_fence_is_not_a_label(self):
        fenced = {"S2": "### S2 Title\n\n```\nCommand: true\nExpected: fine\n```\n"}
        self.assertFails(pack(override=fenced), "S2 has no `Command:` line")

    def test_rollback_needs_a_verified_disarm_before_abort(self):
        # Round 5 item 7: removing the disarm still passed the pack checker.
        no_disarm = HEAD.replace('chk disarm --profile "$PROFILE"', "true")
        self.assertFails(pack(head=no_disarm), "has no `chk disarm` command")
        prose_only = HEAD.replace('```sh\nchk disarm --profile "$PROFILE"\n```', "Run chk disarm.")
        self.assertFails(pack(head=prose_only), "has no `chk disarm` command")
        swapped = HEAD.replace('chk disarm --profile "$PROFILE"', "@@").replace("chk abort", 'chk disarm --profile "$PROFILE"')
        self.assertFails(pack(head=swapped.replace("@@", "chk abort")), "must run `chk disarm` before `chk abort`")
        self.assertFails(pack(head=HEAD.replace("chk abort", "true")), "must run `chk disarm` before `chk abort`")
        self.assertFails(pack(head="## Rollback\n\nAbort first.\n"), "no `### After cutover confirm`")

    def test_failed_disarm_branch_boots_the_daemon_out(self):
        # Round 6 suggestion: removing the failed-disarm bootout call still passed the pack checker.
        self.assertFails(pack(head=HEAD.replace("chk bootout", "true")), "has no `chk bootout` command")
        prose_only = HEAD.replace("```sh\nsudo -v\nchk bootout\n```", "Run chk bootout.")
        self.assertFails(pack(head=prose_only), "has no `chk bootout` command")
        self.assertFails(pack(head=HEAD.replace("chk bootout", "chk bootouts")), "has no `chk bootout` command")
        self.assertFails(pack(head=HEAD.replace(DISARM_FAILED, "")), "no `### Disarm not verified`")

    def test_s4_and_s5_repeat_s1_to_s3_after_each_change(self):
        for name in ("S4", "S5"):
            with self.subTest(name=name):
                self.assertFails(pack(override={name: two_changes(name, second='chk leakwatch --vps4 "$VPS4"')}),
                                 "%s runs `chk s123` 1 time(s)" % name)
                self.assertFails(pack(override={name: two_changes(name, first="true", second="true")}),
                                 "%s runs `chk s123` 0 time(s)" % name)
                self.assertFails(pack(override={name: two_changes(name, second="chk s1234")}), "1 time(s)")
        self.assertEqual(self.problems(pack(override={"S5": two_changes("S5", first="chk s123 && chk s123",
                                                                         second="true")})), [])

    def test_s6_keeps_both_wifi_cycles(self):
        self.assertFails(pack(override={"S6": s6(exclude="Switch to Except these networks.\n")}), "S6 has 1 Wi-Fi cycle")
        self.assertFails(pack(override={"S6": s6(include="", exclude="")}), "S6 has 0 Wi-Fi cycle")
        self.assertFails(pack(override={"S6": s6(until="chk status")}), "no `chk phasewatch --until active` after")
        self.assertFails(pack(override={"S6": s6(hold="chk status")}), "no `chk phasewatch --hold idle` after")
        fenced_cycle = s6(exclude="```\nTurn Wi-Fi off, then turn it back on.\n```\n")
        self.assertFails(pack(override={"S6": fenced_cycle}), "S6 has 1 Wi-Fi cycle")

    def test_s6_waits_for_idle_before_the_exclude_cycle(self):
        # VER-M04-SITTING: `--hold idle` failed on its first sample while the tunnel was still stopping.
        needle = "no `chk phasewatch --until idle` between"
        self.assertFails(pack(override={"S6": s6(wait="chk status phase")}), needle)
        self.assertFails(pack(override={"S6": s6(wait="chk phasewatch --until idler")}), needle)
        late = s6(wait="true", hold="chk phasewatch --until idle\nchk phasewatch --hold idle")
        self.assertFails(pack(override={"S6": late}), needle)

    def test_c2_expects_the_active_phase_and_no_operation_in_flight(self):
        # VER-M04-SITTING: the armed-trial check also asserts phase=active and operationInFlight=false.
        needle = "C2 has no `chk status` line expecting"
        for dropped in ("--expect phase=active", "--expect operationInFlight=false", "--expect protection=protected"):
            with self.subTest(dropped=dropped):
                self.assertFails(pack(override={"C2": section("C2", START + "\n" + ARMED.replace(dropped, ""))}),
                                 needle)
        self.assertFails(pack(override={"C2": section("C2", START + "\n" + ARMED.replace("=false", "=falsey"))}),
                         needle)
        split = ARMED.replace(" --expect phase", "\nchk status --expect phase")
        self.assertFails(pack(override={"C2": section("C2", START + "\n" + split)}), needle)
        quoted = ARMED.replace("--expect phase=active", "--expect 'phase=active'")
        self.assertEqual(self.problems(pack(override={"C2": section("C2", START + "\n" + quoted)})), [])
        prose = section("C2", START) + "Run chk status --expect phase=active --expect operationInFlight=false.\n"
        self.assertFails(pack(override={"C2": prose}), needle)

    def test_rollback_and_prerequisites_need_no_labels(self):
        self.assertEqual(self.problems(pack()), [])

    def test_candidate_tag_match_passes_and_mismatch_fails(self):
        tag = CS.helper_tag()
        self.assertEqual(tag, "M04-rc9")
        self.assertEqual(CS.tag_problems("build the tag %s here" % tag, tag), [])
        self.assertEqual(CS.tag_problems("no tag", tag), [])
        self.assertEqual(len(CS.tag_problems("build the tag M04-rc here", tag)), 1)
        self.assertEqual(len(CS.tag_problems("old M04-rc2 and %s" % tag, tag)), 1)
        self.assertEqual(len(CS.tag_problems("old product build M04-rc3", tag)), 1)
        self.assertEqual(len(CS.tag_problems("path /x/M04-rc2/y", tag)), 1)
        self.assertEqual(len(CS.tag_problems("x", None)), 1)
        self.assertIn("M04-rc2", self.problems(pack() + "\nbuild M04-rc2\n")[-1])

    def test_candidate_tag_delimiters(self):
        for suffix in ("", " ", "`", "/", ".", ")", "\n"):
            with self.subTest(suffix=suffix):
                self.assertEqual(CS.tag_problems("M04-rc6" + suffix, "M04-rc6"), [])
                self.assertEqual(len(CS.tag_problems("M04-rc3" + suffix, "M04-rc6")), 1)
        for text in ("M04-rc30", "M04-rc60", "M04-rc"):
            with self.subTest(text=text):
                self.assertEqual(len(CS.tag_problems(text, "M04-rc6")), 1)
        for suffix in ("x", "_notes", "-notes"):
            with self.subTest(suffix=suffix):
                self.assertEqual(CS.tag_problems("M04-rc3" + suffix, "M04-rc6"), [])


class CommandLine(unittest.TestCase):
    def run_check(self, *args):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, timeout=60)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.md"
            good.write_text(pack(), encoding="utf-8")
            bad = Path(tmp) / "bad.md"
            bad.write_text(pack(order=list(reversed(ORDER))), encoding="utf-8")
            binary = Path(tmp) / "binary.md"
            binary.write_bytes(b"\xff\xfe\x00")
            self.assertEqual(self.run_check(str(good)).returncode, 0)
            failed = self.run_check(str(bad))
            self.assertEqual(failed.returncode, 1)
            self.assertIn("check-sitting:", failed.stderr)
            self.assertEqual(self.run_check(str(Path(tmp) / "missing.md")).returncode, 2)
            self.assertEqual(self.run_check(str(binary)).returncode, 2)
            self.assertEqual(self.run_check().returncode, 2)
            self.assertEqual(self.run_check(str(good), str(good)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
