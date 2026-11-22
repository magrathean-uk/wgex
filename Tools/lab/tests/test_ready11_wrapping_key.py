# SPDX-License-Identifier: MIT
"""M01-T04 ready11: install mode keeps the daemon's wrapping key readable across ad hoc Lab reinstalls, with no prompt."""
import unittest

import test_live_replay as replay

LIVE, RecordedRunner, ROOT = replay.LIVE, replay.RecordedRunner, replay.ROOT
SCRIPT = ROOT / "Tools/lab/tart/guest/wrapping-key.sh"
ACTIONS = ROOT / "Tools/lab/tart/guest/verdict-actions.sh"


class InstallModeTests(unittest.TestCase):
    def test_reinstalled_daemon_must_read_the_wrapping_key_before_provenance(self):
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04")
        commands = [" ".join(c) for c in runner.commands]
        ordered = ["lab install", "verdict-actions.sh refresh-install", "verdict-actions.sh secure-install-status",
                   "sw_vers -productVersion", "lab profile full4"]
        indices = [next(i for i, c in enumerate(commands) if text in c) for text in ordered]
        self.assertEqual(indices, sorted(indices))
        installation = result["installation"]
        self.assertEqual((installation["wrappingKey"], installation["secureInstall"]), ("re-trusted", "verified"))
        self.assertIs(installation["wrappingKeyReadable"], True)
        self.assertTrue(result["prepareCompleted"] and result["rowCompleted"])

    def test_unreadable_key_fails_prepare_with_the_reported_state(self):
        for state, recorded in (("needsAttention(wrappingKeyUnavailable)", "needsAttention(wrappingKeyUnavailable)"),
                                ("needsAttention(wrappingKeyRepairFailed)", "needsAttention(wrappingKeyRepairFailed)"),
                                ("unknown", "unknown"), ("<script>", "unreadable")):
            runner = RecordedRunner()
            runner.secure_install = state
            runner.wrapping_key_line = b"wrapping key present for com.magrathean.WGEXApp.dev.daemon; not escrowed by the lab, left unchanged\n"
            _, result = replay.LiveReplayTests().run_recorded("M5.1-04", runner, accepted=False)
            with self.subTest(state=state):
                self.assertFalse(result["prepareCompleted"] or result["rowCompleted"])
                self.assertEqual(result["installation"]["secureInstall"], recorded)
                self.assertEqual(result["installation"]["wrappingKey"], "unescrowed")
                self.assertIs(result["installation"]["wrappingKeyReadable"], False)
                self.assertTrue(any("wrappingKeyUnreadable" in gap for gap in result["gaps"]))
                self.assertFalse(any("lab profile" in " ".join(c) for c in runner.commands))

    def test_missing_doctor_reply_is_unreadable(self):
        class Silent(RecordedRunner):
            def run(self, argv, **kwargs):
                if argv[-1].endswith("verdict-actions.sh secure-install-status"):
                    self.commands.append(list(argv))
                    self.environments.append(kwargs.get("env"))
                    return self.reply(argv, b"")
                return super().run(argv, **kwargs)
        _, result = replay.LiveReplayTests().run_recorded("M5.1-04", Silent(), accepted=False)
        self.assertEqual(result["installation"]["secureInstall"], "unreadable")
        self.assertTrue(any("wrappingKeyUnreadable" in gap for gap in result["gaps"]))

    def test_owner_asserted_snapshot_skips_the_key_check(self):
        runner, result = replay.LiveReplayTests().run_recorded("M5.1-04", no_install=True)
        self.assertFalse(any("secure-install-status" in " ".join(c) for c in runner.commands))
        self.assertNotIn("wrappingKeyReadable", result["installation"])

    def test_outcome_words_from_the_install_output(self):
        cases = {
            b"wrapping key re-trusted for s; decrypt ACL trusts installed daemon cdhash x\n": "re-trusted",
            b"wrapping key unchanged for s; decrypt ACL trusts installed daemon cdhash x\n": "unchanged",
            b"wrapping key restored from the lab escrow for s\n": "restored",
            b"wrapping key provisioned and escrowed for s\n": "provisioned",
            b"wrapping key present for s; not escrowed by the lab, left unchanged\n": "unescrowed",
            b"wrapping key present for s\n": "present",
            b"wrapping key absent; the daemon provisions it during Secure Install\n": "absent",
            b"Contents/Info.plist: OK\n": "unreported", b"": "unreported", None: "unreported",
        }
        for output, word in cases.items():
            with self.subTest(output=output):
                self.assertEqual(LIVE.wrapping_key_outcome(output), word)


class GuestScriptTests(unittest.TestCase):
    """Static contract of the guest scripts; they run only inside a guarded lab guest."""

    def setUp(self):
        self.source = SCRIPT.read_text()

    def test_guard_precedes_every_privileged_step(self):
        first = min(self.source.index(word) for word in ("sudo -n security delete", "sudo -n install", "sudo -n tee"))
        self.assertLess(self.source.index("guest_guard"), first)

    def test_key_bytes_never_reach_argv_or_output(self):
        self.assertNotIn("security add-generic-password", self.source)  # only through `security -i` on stdin
        self.assertIn("sudo -n security -i >/dev/null 2>&1", self.source)
        self.assertNotRegex(self.source, r"find-generic-password[^\n]*-[gw]\b")
        self.assertNotRegex(self.source, r"security dump-keychain[^\n]*\s-d\b")
        self.assertNotRegex(self.source, r"echo[^\n]*\$key|printf '%s\\n' \"\$key\"")
        self.assertIn("set +x", self.source)

    def test_escrow_is_root_only_inside_the_guest_and_written_before_the_keychain(self):
        self.assertIn("escrow_dir=/var/db/wgex-lab-keys", self.source)
        self.assertIn('sudo -n install -d -m 0700 -o root -g wheel "$escrow_dir"', self.source)
        self.assertIn('sudo -n install -m 0600 -o root -g wheel /dev/null "$escrow"', self.source)
        fresh = self.source[self.source.rindex('key="$(head -c 32 /dev/urandom'):]
        self.assertLess(fresh.index('sudo -n tee "$escrow"'), fresh.index('add_key "$key"'))

    def test_retrust_reuses_the_escrowed_bytes_and_binds_to_the_item(self):
        retrust = self.source[self.source.index("# Same bytes, new trusted daemon"):]
        retrust = retrust[:retrust.index("\nfi\n")]
        self.assertLess(retrust.index('key="$(read_escrow)"'), retrust.index("delete-generic-password"))
        self.assertLess(retrust.index("delete-generic-password"), retrust.index('add_key "$key"'))
        self.assertIn('verify_trust "wrapping key re-trusted"', retrust)
        # An item the lab did not create (no escrow or another creation date) is never deleted or re-added.
        guard = self.source[self.source.index("if present; then\n  if ! escrowed"):self.source.index("# Same bytes")]
        self.assertIn('"$(sudo -n cat "$binding")" != "$(created)"', guard)
        self.assertIn("exit 0", guard)

    def test_replacing_an_unescrowed_key_refuses_ciphertext(self):
        replace = self.source[self.source.index('if present && [[ "$replace" == 1 ]]'):self.source.index("if present; then\n  if ! escrowed")]
        self.assertLess(replace.index("elif ciphertext; then"), replace.index("delete-generic-password"))
        self.assertIn("exit 1", replace[:replace.index("delete-generic-password")])
        self.assertIn("-name '*.blob'", self.source)

    def test_acl_reads_parse_dump_lines_only(self):
        self.assertRegex(self.source, r"requirement: cdhash H")
        self.assertIn('"acct"<blob>="wrapping-key-v1"', self.source)
        self.assertIn("codesign -d --verbose=4", self.source)
        self.assertIn("more than one wrapping key item", self.source)

    def test_secure_install_status_waits_for_the_relaunched_daemon(self):
        actions = ACTIONS.read_text()
        block = actions[actions.index("  secure-install-status)"):]
        block = block[:block.index(";;")]
        self.assertIn('"$cli" doctor --json', block)
        self.assertRegex(block, r"attempt < [0-9]+")
        self.assertNotRegex(block, r"sudo|security ")
        self.assertLess(actions.index("guest_guard"), actions.index("  secure-install-status)"))


if __name__ == "__main__":
    unittest.main()
