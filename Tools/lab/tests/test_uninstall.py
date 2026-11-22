# SPDX-License-Identifier: MIT
"""UNINSTALL (M03-T15, DEC-037 item 4, DEC-040): the catalogue entry, the reducers on recorded guest text, the row's checks on
their fixture, the guest actions with stubbed tools, and the real driver against a fake guest. Never a VM."""
import copy
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_live_replay as replay
import test_run8_rows as run8

ROOT, LIVE, V = replay.ROOT, replay.LIVE, replay.V
U = V.UNINSTALL
SCRIPT = ROOT / "Tools/lab/uninstall/guest-uninstall.sh"
ROWS = json.loads((ROOT / "Tools/lab/rows.json").read_text())["rows"]
FIXTURE = json.loads((ROOT / "Tools/lab/tests/fixtures/rows/uninstall.json").read_text())
PROFILE = "00000000-0000-4000-8000-000000000107"

# Recorded on ready11 (macOS 26.6.2) during the M03-T15 exploration: netstat -rn before the tunnel and while protected.
ROUTES_BASELINE = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.64.1       UGScg                 en0
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#7             UCS                   en0      !
192.168.64         link#7             UCS                   en0      !
192.168.64.1/32    link#7             UCS                   en0      !
192.168.64.1       02:00:5e:10:00:06  UHLWIir               en0   1091
192.168.64.232/32  link#7             UCS                   en0      !
192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !
224.0.0/4          link#7             UmCS                  en0      !
224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0
255.255.255.255/32 link#7             UCS                   en0      !

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
"""
ROUTES_PROTECTED = ROUTES_BASELINE.replace(
    "default            192.168.64.1       UGScg                 en0\n",
    "0/1                link#12            US2cg               utun4\ndefault            192.168.64.1       UGScg                 en0\n"
    "10.77.0.2          10.77.0.2          UH                  utun4\n128.0/1            link#12            US2c                utun4\n"
    "192.0.2.1          192.168.64.1       UGHS2I                en0\n").replace("UHLWIir               en0   1091", "UHLWIir               en0   1155")
DNS_BASELINE = """DNS configuration

resolver #1
  search domain[0] : localdomain
  nameserver[0] : 192.168.64.1
  if_index : 7 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : localdomain
  nameserver[0] : 192.168.64.1
  if_index : 7 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
"""
DNS_PROTECTED = DNS_BASELINE.replace("""resolver #1
  search domain[0] : localdomain
  nameserver[0] : 192.168.64.1
  if_index : 7 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
""", """resolver #1
  search domain[0] : localdomain
  nameserver[0] : 10.77.0.1
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 102200

resolver #2
  nameserver[0] : 192.168.64.1
  if_index : 7 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  order    : 200000
""", 1)
IFCONFIG_PROTECTED = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.64.232 netmask 0xffffff00 broadcast 192.168.64.255
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::1%utun3 prefixlen 64 scopeid 0xd
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
\tinet 10.77.0.2 --> 10.77.0.2 netmask 0xffffffff
"""


def observation():
    return copy.deepcopy(FIXTURE["pass"])


def checks(value):
    return {item["name"]: item for item in V.row_checks("uninstall", value)}


def failed(value):
    return sorted(name for name, item in checks(value).items() if not item["met"])


def edit(value, path, replacement):
    holder = value
    for key in path[:-1]:
        holder = holder[key]
    holder[path[-1]] = replacement
    return value


class CatalogueTests(unittest.TestCase):
    def test_the_row_is_live_in_the_catalogue_scope_and_mirror(self):
        row = ROWS["UNINSTALL"]
        self.assertNotIn("gap", row)
        self.assertEqual((row["action"], row["checks"], row["profile"], row["connect"]), ("uninstall", "uninstall", "full4", False))
        self.assertIn(row["checks"], V.ROW_CHECKS)
        self.assertNotIn("uninstall", LIVE.LEAD_CONTROL_KINDS, "the tunnel works again at the end, so the tail control trails")
        self.assertIn("UNINSTALL", (ROOT / "Tools/lab/scope-v2.txt").read_text().split())

    def test_every_criterion_has_an_expectation_and_every_check_has_a_failing_fixture(self):
        expected = " ".join(ROWS["UNINSTALL"]["expected"])
        for words in ("kill switch armed", "--purge --yes", "tunnel is stopped", "No WGEX pf rule", "No WGEX route", "DNS as before the tunnel",
                      "wgex status reports the uninstalled state", "refused", "launchd job and the login item", "does not hang",
                      "profiles are still there", "only the journal", "fresh secure install from the app", "a tunnel starts"):
            self.assertIn(words, expected)
        names = {item["name"] for item in V.row_checks("uninstall", observation())}
        self.assertEqual(names, {case["expectation"] for case in FIXTURE["failing"]})
        self.assertEqual(len(names), 32)
        self.assertTrue(all(item["met"] for item in V.row_checks("uninstall", observation())))
        self.assertLess((ROOT / "Tools/lab/tests/fixtures/rows/uninstall.json").stat().st_size, 50000)

    def test_each_failing_fixture_rejects_its_own_expectation_only_and_each_passing_variant_passes(self):
        for case in FIXTURE["failing"]:
            with self.subTest(expectation=case["expectation"]):
                value = observation()
                for path, replacement in case["set"]:
                    edit(value, path, replacement)
                self.assertEqual(failed(value), [case["expectation"]])
        for case in FIXTURE["passing"]:
            with self.subTest(case=case["name"]):
                value = observation()
                for path, replacement in case["set"]:
                    edit(value, path, replacement)
                self.assertEqual(failed(value), [])

    def test_the_dry_run_replays_the_rows_checks_with_every_failing_fixture_covered(self):
        spec = replay.importlib.util.spec_from_file_location("uninstall_run", ROOT / "Tools/lab/verdict-run.py")
        run = replay.importlib.util.module_from_spec(spec)
        spec.loader.exec_module(run)
        result = run.replay_row_checks(ROWS["UNINSTALL"], {})
        self.assertTrue(result["rowChecksMet"])
        self.assertEqual(result["failingFixturesUncovered"], [])


class ReducerTests(unittest.TestCase):
    def test_routes_drop_link_layer_entries_and_the_ipv6_section(self):
        baseline = U.routes(ROUTES_BASELINE)
        self.assertIn("default 192.168.64.1 UGScg en0", baseline)
        self.assertFalse(any("62:3e:5f" in line or "ff:ff:ff" in line or "1:0:5e" in line for line in baseline), "flag L lines are left out")
        self.assertFalse(any("fe80" in line for line in baseline), "Internet6 is not read")
        protected = U.routes(ROUTES_PROTECTED)
        self.assertEqual(sorted(set(protected) - set(baseline)), ["0/1 link#12 US2cg utun4", "10.77.0.2 10.77.0.2 UH utun4",
                                                                  "128.0/1 link#12 US2c utun4", "192.0.2.1 192.168.64.1 UGHS2I en0"])
        self.assertEqual(U.routes(ROUTES_PROTECTED.replace("1155", "1200")), protected, "an ARP expiry change is not a route change")
        self.assertEqual(U.routes(""), [])

    def test_resolvers_keep_servers_and_domains_of_both_sections_and_drop_reach_flags_and_order(self):
        baseline = U.resolvers(DNS_BASELINE)
        self.assertEqual(baseline, ["domain=local;options=mdns", "if=en0;nameserver=192.168.64.1;search domain=localdomain",
                                    "scoped:if=en0;nameserver=192.168.64.1;search domain=localdomain"])
        self.assertEqual(U.resolvers(DNS_BASELINE.replace("0x00020002 (Reachable,Directly Reachable Address)", "0x00000000 (Not Reachable)")),
                         baseline)
        protected = U.resolvers(DNS_PROTECTED)
        self.assertIn("nameserver=10.77.0.1;search domain=localdomain", protected)
        self.assertNotEqual(protected, baseline)
        self.assertEqual(U.resolvers(""), [])

    def test_a_tunnel_resolver_left_only_in_the_scoped_section_fails_the_dns_check(self):
        # REV-M03-T15 item 1: the default section as before, the tunnel's resolver still scoped to its utun.
        scoped = DNS_BASELINE + "\nresolver #2\n  nameserver[0] : 10.77.0.1\n  if_index : 12 (utun4)\n  flags    : Scoped, Request A records\n"
        default = "DNS configuration (for scoped queries)"
        self.assertEqual(U.resolvers(scoped.split(default)[0]), U.resolvers(DNS_BASELINE.split(default)[0]), "the default section alone is equal")
        self.assertIn("scoped:if=utun4;nameserver=10.77.0.1", U.resolvers(scoped))
        for variant in U.VARIANTS:
            with self.subTest(variant=variant):
                value = edit(observation(), ["uninstall", "baseline", "resolvers"], U.resolvers(DNS_BASELINE))
                for other in U.VARIANTS:
                    edit(value, ["uninstall", "variants", other, "after", "observation", "resolvers"],
                         U.resolvers(scoped if other == variant else DNS_BASELINE))
                self.assertEqual(failed(value), [variant + ":dnsAsBeforeTunnel"])
        value = edit(observation(), ["uninstall", "variants", "keep", "after", "observation", "resolvers"],
                     [entry for entry in FIXTURE["pass"]["uninstall"]["baseline"]["resolvers"] if not entry.startswith("scoped:")])
        self.assertEqual(failed(value), ["keep:dnsAsBeforeTunnel"], "a scoped resolver lost after the uninstall is a difference too")

    def test_the_tunnel_interface_is_the_utun_with_the_tunnel_address(self):
        self.assertEqual(U.tunnel_interfaces(IFCONFIG_PROTECTED), ["utun4"])
        self.assertEqual(U.tunnel_interfaces(IFCONFIG_PROTECTED.replace("10.77.0.2 --> 10.77.0.2", "10.9.0.2 --> 10.9.0.2")), [])
        self.assertEqual(U.tunnel_interfaces(""), [])

    def test_the_observation_reduction_counts_filter_rules_only(self):
        reduced = U.reduce_observation(dict(status=dict(phase="active", protection="protected"), referenceCount=1, routes=ROUTES_PROTECTED,
                                            dns=DNS_PROTECTED, ifconfig=IFCONFIG_PROTECTED,
                                            rules="@0 block drop quick all\n  [ Evaluations: 1 ]\npass out quick on utun4 all\n"))
        self.assertEqual((reduced["ruleLines"], reduced["tunnelInterfaces"], reduced["referenceCount"]), (2, ["utun4"], 1))
        self.assertEqual(U.reduce_observation(None)["routes"], [])

    def test_status_matches_the_m05_t14_json_field_and_text_line_for_each_variant(self):
        keep_line = "uninstall: completed; the service is uninstalled; open WGEX to finish removing the background service and login item"
        purge_line = keep_line.replace("completed;", "completed (purge);")
        def status(purge, **extra):
            return dict(phase="idle", uninstall=dict(dict(completed=True, purgeState=purge, pendingStep=None), **extra))
        self.assertTrue(U.status_uninstalled(status(False), keep_line, False))
        self.assertTrue(U.status_uninstalled(status(True), purge_line, True))
        # What the product printed before M05-T14: no uninstall field and no line.
        self.assertFalse(U.status_uninstalled(dict(phase="idle", protection="unprotected"), "none", False))
        self.assertFalse(U.status_uninstalled(dict(phase="idle", uninstall=None), "none", False), "null while no uninstall is held")
        self.assertFalse(U.status_uninstalled(status(False, completed=False, pendingStep="removeRoutes"),
                                              "uninstall: in progress; step removeRoutes pending; run wgex uninstall again to resume", False))
        self.assertFalse(U.status_uninstalled(status(False, pendingStep="removeRoutes"), keep_line, False))
        self.assertFalse(U.status_uninstalled(status(False), purge_line, False), "a keep must not print (purge)")
        self.assertFalse(U.status_uninstalled(status(True), keep_line, True), "a purge must say (purge)")
        self.assertFalse(U.status_uninstalled(status(False), keep_line, True), "purgeState must match the variant")
        self.assertFalse(U.status_uninstalled(status(False), "none", False), "the text form must carry the line too")
        self.assertFalse(U.status_uninstalled(dict(phase="idle", uninstallState="uninstalled"), keep_line, False), "only the real field")
        self.assertFalse(U.status_uninstalled(None, None, False))


class CheckTests(unittest.TestCase):
    def test_the_status_the_product_printed_in_the_exploration_fails_only_the_status_checks(self):
        value = observation()
        for variant in U.VARIANTS:
            edit(value, ["uninstall", "variants", variant, "after", "status", "status"], dict(phase="idle", protection="unprotected"))
        self.assertEqual(failed(value), ["keep:statusReportsUninstalled", "purge:statusReportsUninstalled"])

    def test_a_listed_but_empty_anchor_passes_and_any_rule_table_nested_anchor_or_reference_fails(self):
        for key, bad in (("anchorRules", 1), ("anchorTables", 1), ("anchorNested", 1), ("references", 1), ("anchorRules", None)):
            with self.subTest(key=key, value=bad):
                value = observation()
                edit(value, ["uninstall", "variants", "keep", "after", "pf", key], bad)
                self.assertEqual(failed(value), ["keep:noWgexPfRule"])

    def test_a_route_left_from_the_tunnel_or_a_baseline_route_lost_fails(self):
        baseline = FIXTURE["pass"]["uninstall"]["baseline"]["routes"]
        for routes in (baseline[1:], baseline + ["10.77.0.2 10.77.0.2 UH utun4"]):
            with self.subTest(routes=len(routes)):
                value = edit(observation(), ["uninstall", "variants", "purge", "after", "observation", "routes"], routes)
                self.assertIn("purge:noWgexRoute", failed(value))

    def test_a_stop_answered_as_done_is_recorded_not_judged_and_an_unauthorised_refusal_does_not_count(self):
        value = edit(observation(), ["uninstall", "variants", "keep", "after", "refused", "down"], [0, "none"])
        self.assertEqual(failed(value), [])
        value = edit(observation(), ["uninstall", "variants", "keep", "after", "refused", "up"], [4, "unauthorised"])
        self.assertEqual(failed(value), ["keep:mutatingRequestsRefused"], "only the uninstall fence's refusal counts")

    def test_a_tunnel_that_starts_only_after_the_drivers_daemon_restart_fails(self):
        value = edit(observation(), ["uninstall", "variants", "keep", "freshInstall", "tunnel"],
                     dict(protected=False, driverRestartedDaemon=True, protectedAfterDaemonRestart=True))
        self.assertEqual(failed(value), ["keep:tunnelStartsAfterFreshInstall"])
        value = edit(observation(), ["uninstall", "variants", "purge", "freshInstall", "tunnel"], dict(protected=True, driverRestartedDaemon=True))
        self.assertEqual(failed(value), ["purge:tunnelStartsAfterFreshInstall"], "a run that needed the restart fails whatever it records")

    def test_a_quit_that_needed_the_drivers_stop_app_fails(self):
        value = edit(observation(), ["uninstall", "variants", "purge", "finish", "quit"], dict(pressed=True, exited=True, driverStopped="term"))
        self.assertEqual(failed(value), ["purge:finalQuitEndsApp"])

    def test_the_purge_state_root_allows_only_the_journal_reduced_to_the_marker(self):
        root = ["uninstall", "variants", "purge", "after", "stateRoot"]
        for path, bad in (([*root, "files"], ["journal.json", "status-sequence.json"]), ([*root, "journal", "entries"], "array:46"),
                          ([*root, "journal", "intent"], "object:2"), ([*root, "journal", "uninstall.purgeState"], "false"),
                          ([*root, "root"], "absent"), ([*root, "journal"], None), ([*root, "files"], None)):
            with self.subTest(path=path[-1], value=bad):
                self.assertEqual(failed(edit(observation(), path, bad)), ["purge:stateRootMarkerOnly"])

    def test_the_purged_journal_needs_every_field_of_its_exact_type_and_the_generation_fence(self):
        # REV-M03-T15 item 2: arbitrary retained objects, a missing or lowered generation, non-default settings, a policy other
        # than disconnected or a field of another type each fail; the fixture pass is the document the purge writes.
        for key, bad in (("generation", None), ("generation.value", None), ("generation", "string"), ("generation.value", 3),
                         ("generation.value", True), ("schemaVersion", "string"), ("schemaVersion.value", "2"), ("journalSequence", None),
                         ("settings", "object:5"), ("settings", None), ("settings.default", "false"), ("settings.default", True),
                         ("pfPolicy", "object:2"), ("pfPolicy.disconnected", "false"), ("pfPolicy.disconnected", None),
                         ("uninstall", "array:3"), ("uninstall", None), ("uninstall.completed", None), ("lastGoodAddresses", "array:0"),
                         ("resources", "object:0"), ("pendingSecretDeletions", "array:1"), ("cutover", "object:2"), ("pfToken", "string"),
                         ("settings.lockdown", "true")):
            with self.subTest(key=key, value=bad):
                value = observation()
                holder = value["uninstall"]["variants"]["purge"]["after"]["stateRoot"]["journal"]
                if bad is None:
                    holder.pop(key, None)
                else:
                    holder[key] = bad
                self.assertEqual(failed(value), ["purge:stateRootMarkerOnly"])
        for optional in ("entries", "resources", "pendingSecretDeletions", "lastGoodAddresses"):
            with self.subTest(absent=optional):
                value = observation()
                del value["uninstall"]["variants"]["purge"]["after"]["stateRoot"]["journal"][optional]
                self.assertEqual(failed(value), [], "an empty container the encoder omits is not a retained object")
        before = ["uninstall", "variants", "purge", "before", "stateRoot"]
        for path, bad in (([*before, "journal", "generation.value"], 6), ([*before, "journal", "generation.value"], 0),
                          ([*before, "journal"], "unreadable"), (before, None)):
            with self.subTest(before=path[-1], value=bad):
                self.assertEqual(failed(edit(observation(), path, bad)), ["purge:stateRootMarkerOnly"])
        self.assertEqual(failed(edit(observation(), [*before, "journal", "generation.value"], 5)), [],
                         "a purge that allocated no generation after the protected one keeps it")
        self.assertEqual(failed(edit(observation(), ["uninstall", "variants", "purge", "after", "stateRoot", "journal"], "unreadable")),
                         ["purge:stateRootMarkerOnly"])

    def test_a_failed_guest_read_never_passes_as_an_absence_or_a_zero(self):
        # REV-M03-T15 item 3: "unknown" from services, pf or the state root fails the check that reads it.
        cases = ((["keep", "finish", "services", "btmDaemon"], "keep:serviceRemovedByApp"),
                 (["keep", "finish", "services", "launchdJob"], "keep:serviceRemovedByApp"),
                 (["keep", "finish", "services", "daemonPid"], "keep:serviceRemovedByApp"),
                 (["keep", "finish", "services", "btmApp"], "keep:loginItemRemovedByApp"),
                 (["purge", "freshInstall", "services", "daemonPid"], "purge:freshInstallRestoresDaemon"),
                 (["purge", "freshInstall", "services", "launchdJob"], "purge:freshInstallRestoresDaemon"),
                 (["keep", "after", "pf", "anchorListed"], "keep:noWgexPfRule"),
                 (["keep", "after", "pf", "anchorRules"], "keep:noWgexPfRule"),
                 (["keep", "after", "pf", "anchorTables"], "keep:noWgexPfRule"),
                 (["keep", "after", "pf", "anchorNested"], "keep:noWgexPfRule"),
                 (["purge", "after", "pf", "references"], "purge:noWgexPfRule"),
                 (["purge", "before", "pf", "anchorRules"], "purge:protectedBefore"),
                 (["purge", "after", "stateRoot", "root"], "purge:stateRootMarkerOnly"),
                 (["purge", "after", "stateRoot", "files"], "purge:stateRootMarkerOnly"))
        for path, name in cases:
            with self.subTest(path=path):
                self.assertEqual(failed(edit(observation(), ["uninstall", "variants", *path], "unknown")), [name])
        self.assertEqual(failed(edit(observation(), ["uninstall", "variants", "keep", "after", "pf", "anchorRules"], False)),
                         ["keep:noWgexPfRule"], "a boolean is not a count")

    def test_a_missing_variant_fails_every_check_of_that_variant(self):
        value = observation()
        del value["uninstall"]["variants"]["purge"]
        names = failed(value)
        self.assertEqual(len(names), 16)
        self.assertTrue(all(name.startswith("purge:") for name in names))


def helper(name):
    """A shell function of the guest script, whole."""
    text = SCRIPT.read_text()
    start = text.index(f"\n{name}() {{\n") + 1
    return text[start:text.index("\n}\n", start) + 3]


def block(name):
    """One action of the guest script, as the shell sees it between its label and the closing ;;."""
    text = SCRIPT.read_text()
    start = text.index(f"\n  {name})\n") + 1
    end = text.index("\n    ;;\n", start) + len("\n    ;;\n")
    return text[start:end]


class GuestActionTests(unittest.TestCase):
    def run_action(self, name, *args, stub="", work=None):
        program = (f'set -euo pipefail\nlab_user=labuser\napp=/Applications/WGEX.app\ncli=/fixture/wgex\nroot="/Library/Application Support/WGEX"\n'
                   f'stage={json.dumps(str(ROOT / "Tools/lab/tart/guest"))}\nwork={json.dumps(work or "/nonexistent")}\n'
                   f'now() {{ echo 1.000; }}\nlabel() {{ printf com.magrathean.WGEXApp.dev.daemon; }}\n{helper("btm_disposition")}{helper("pf_count")}{stub}\n'
                   f'set -- {name} {" ".join(args)}\ncase "$1" in\n{block(name)}\nesac\n')
        return subprocess.run(["bash", "-c", program], capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"))

    def test_the_cli_result_is_running_until_its_code_exists_then_fixed_fields_only(self):
        work = Path(replay.tempfile.mkdtemp(dir=os.environ["TMPDIR"]))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(work)])
        self.assertEqual(self.run_action("cli-result", work=str(work)).stdout, "rc=running\n")
        (work / "cli.rc").write_text("0\n")
        (work / "cli.out").write_text('{"next":"open WGEX to finish removing the background service and login item","purge":true,"result":"uninstalled"}\n')
        self.assertEqual(self.run_action("cli-result", work=str(work)).stdout,
                         'rc=0\nreply={"purge":true,"replyReadable":true,"result":"uninstalled"}\n', "the free-text next line never leaves")
        (work / "cli.rc").write_text("19\n")
        (work / "cli.out").write_text('{"error":"uninstallFailed","step":"removeRoutes"}\n')
        self.assertEqual(self.run_action("cli-result", work=str(work)).stdout,
                         'rc=19\nreply={"error":"uninstallFailed","replyReadable":true,"step":"removeRoutes"}\n')
        (work / "cli.out").write_text("not json")
        self.assertIn('reply={"replyReadable":false}', self.run_action("cli-result", work=str(work)).stdout)
        (work / "cli.rc").write_text("x\n")
        self.assertNotEqual(self.run_action("cli-result", work=str(work)).returncode, 0, "a malformed code is refused")

    def test_cli_start_runs_the_product_cli_in_the_console_session_with_yes_and_only_for_the_console_user(self):
        text = block("cli-start")
        self.assertIn('sudo -n launchctl asuser "$1" sudo -n -u "$2" "$3"', text)
        self.assertIn("flags=(uninstall --yes --json)", text)
        self.assertIn("flags=(uninstall --purge --yes --json)", text)
        self.assertIn('stat -f %Su /dev/console)" == "$lab_user"', text)
        result = self.run_action("cli-start", "everything", stub='id() { echo labuser; }\nstat() { echo labuser; }\n')
        self.assertEqual(result.returncode, 2, "only keep or purge")
        result = self.run_action("cli-start", "keep", stub='id() { echo labuser; }\nstat() { echo loginwindow; }\n')
        self.assertEqual(result.returncode, 1, "nothing starts while nobody is logged in at the console")

    def test_status_reduces_to_the_code_phase_protection_and_uninstall_fields(self):
        stub = ('/fixture/wgex() { printf \'%s\\n\' \'{"phase":"idle","protection":"unprotected","activeProfileID":null,'
                '"ownerPFToken":"secret-token","uninstall":{"completed":true,"purgeState":false}}\'; }\n')
        result = self.run_action("status", stub=stub.replace("/fixture/wgex()", "fixture_cli()") + 'cli=fixture_cli\n')
        self.assertEqual(result.stdout, 'rc=0\nstatus={"phase":"idle","protection":"unprotected","uninstall":{"completed":true,"purgeState":false}}\n'
                         'uninstallLine=none\n', result.stderr)
        text = ('fixture_cli() { if [[ "$*" == "status --json" ]]; then printf \'{"phase":"idle","uninstall":{"completed":true,'
                '"purgeState":true,"pendingStep":null}}\\n\'; else printf \'idle (unprotected)\\nuninstall: completed (purge); the service '
                'is uninstalled; open WGEX to finish\\n\'; fi; }\ncli=fixture_cli\n')
        result = self.run_action("status", stub=text)
        self.assertEqual(result.stdout, 'rc=0\nstatus={"phase":"idle","uninstall":{"completed":true,"pendingStep":null,"purgeState":true}}\n'
                         'uninstallLine=uninstall: completed (purge); the service is uninstalled; open WGEX to finish\n', result.stderr)
        self.assertNotIn("secret-token", result.stdout)
        result = self.run_action("status", stub='fixture_cli() { return 1; }\ncli=fixture_cli\n')
        self.assertEqual(result.stdout, 'rc=1\nstatus={"unreadable":true}\nuninstallLine=unreadable\n',
                         "a failed text read is not a missing line")
        self.assertEqual(failed(edit(observation(), ["uninstall", "variants", "keep", "after", "status", "uninstallLine"], "unreadable")),
                         ["keep:statusReportsUninstalled"])

    def test_app_state_and_stop_app_read_only_pgreps_1_as_gone(self):
        # REV-M03-T15 r3 item 1: pgrep's 0 is running, its 1 is exited; any other code is unknown, never an exit.
        for rc, word in ((0, "running"), (1, "exited"), (2, "unknown"), (3, "unknown")):
            with self.subTest(rc=rc):
                result = self.run_action("app-state", stub=f'pgrep() {{ return {rc}; }}\n')
                self.assertEqual((result.returncode, result.stdout), (0, f"app={word}\n"), result.stderr)
        self.assertEqual(self.run_action("stop-app", stub='pgrep() { return 1; }\n').stdout, "stopped=none\n")
        for rc in (2, 3):
            with self.subTest(stop=rc):
                result = self.run_action("stop-app", stub=f'pgrep() {{ return {rc}; }}\nkill() {{ echo killed; }}\n')
                self.assertEqual((result.returncode, result.stdout), (0, "stopped=unknown\n"), result.stderr)
        result = self.run_action("stop-app", stub='pgrep() { echo 812; }\nkill() { [[ "$1" == -TERM ]]; }\n')
        self.assertEqual(result.stdout, "stopped=term\n", result.stderr)

    def test_profiles_count_the_store_and_a_store_that_cannot_be_listed_is_unknown(self):
        with tempfile.TemporaryDirectory() as home:
            stub = f'HOME={shlex.quote(home)}\n'
            self.assertEqual(self.run_action("profiles", PROFILE, stub=stub).stdout, "appProfiles=0\nprofilePresent=false\n",
                             "a missing store is a confirmed absence")
            store = Path(home, "Library/Application Support/WGEX/profiles")
            store.mkdir(parents=True)
            (store / (PROFILE.lower() + ".json")).write_text("{}")
            (store / "11111111-2222-3333-4444-555555555555.json").write_text("{}")
            (store / "notes.txt").write_text("")
            self.assertEqual(self.run_action("profiles", PROFILE, stub=stub).stdout, "appProfiles=2\nprofilePresent=true\n")
            unreadable = 'ls() { return 1; }\n'
            self.assertEqual(self.run_action("profiles", PROFILE, stub=stub + unreadable).stdout,
                             "appProfiles=unknown\nprofilePresent=unknown\n", "a failed listing is not an empty store")
            for item in store.iterdir():
                item.unlink()
            store.rmdir()
            store.write_text("")
            self.assertEqual(self.run_action("profiles", PROFILE, stub=stub).stdout, "appProfiles=unknown\nprofilePresent=unknown\n")
        live = LIVE.Session("fixture", {}, runner=replay.RecordedRunner())
        with patch.object(live, "uninstall_action", lambda *a, **k: b"appProfiles=unknown\nprofilePresent=unknown\n"):
            fields = live.uninstall_fields("profiles", PROFILE)
        self.assertEqual(failed(edit(observation(), ["uninstall", "variants", "keep", "finish", "profiles"], fields)), ["keep:appProfilesKept"])

    def test_pf_counts_rules_tables_nested_anchors_and_references(self):
        stub = '''sudo() {
  case "$*" in
    "-n pfctl -a com.apple -s Anchors") printf '  com.apple/200.AirDrop\\n  com.apple/wgex\\n' ;;
    "-n pfctl -a com.apple/wgex -sr") printf 'block drop quick all\\npass out quick on utun4 all\\n' ;;
    "-n pfctl -a com.apple/wgex -sT") printf 'wgex_endpoints\\n' ;;
    "-n pfctl -a com.apple/wgex -s Anchors") ;;
    "-n pfctl -s References") printf 'TOKEN TIMESTAMP     PID        PROCESS\\n  1  9 2026  4    0 days 00:00:12 WGEXDaemon\\n' ;;
  esac
}
'''
        self.assertEqual(self.run_action("pf", stub=stub).stdout, "anchorListed=true\nanchorRules=2\nanchorTables=1\nanchorNested=0\nreferences=0\n")
        empty = 'sudo() { case "$*" in "-n pfctl -a com.apple -s Anchors") printf "  com.apple/200.AirDrop\\n" ;; *) printf "No pf starter references held\\n" ;; esac; }\n'
        result = self.run_action("pf", stub=empty.replace('*) printf "No pf starter references held\\n"', '"-n pfctl -s References") printf "No pf starter references held\\n" ;; *) '))
        self.assertEqual(result.stdout, "anchorListed=false\nanchorRules=0\nanchorTables=0\nanchorNested=0\nreferences=0\n", result.stderr)

    def test_pf_reads_that_fail_are_unknown_not_zero(self):
        # REV-M03-T15 item 3: a failing pfctl is never a confirmed empty anchor or no reference.
        self.assertEqual(self.run_action("pf", stub="sudo() { return 1; }\n").stdout,
                         "anchorListed=unknown\nanchorRules=unknown\nanchorTables=unknown\nanchorNested=unknown\nreferences=unknown\n")
        listed = ('sudo() {\n  case "$*" in\n'
                  '    "-n pfctl -a com.apple -s Anchors") printf "  com.apple/wgex\\n" ;;\n'
                  '    "-n pfctl -a com.apple/wgex -sr") return 1 ;;\n'
                  '    "-n pfctl -s References") return 1 ;;\n'
                  '  esac\n}\n')
        self.assertEqual(self.run_action("pf", stub=listed).stdout,
                         "anchorListed=true\nanchorRules=unknown\nanchorTables=0\nanchorNested=0\nreferences=unknown\n")

    def test_services_reads_that_fail_are_unknown_not_absent(self):
        # REV-M03-T15 item 3: only launchctl's 113, pgrep's 1 and a successful BTM dump without the item are absences.
        stub = 'sudo() { case "$2" in launchctl) return 1 ;; sfltool) return 1 ;; esac; }\npgrep() { return 3; }\n'
        self.assertEqual(self.run_action("services", stub=stub).stdout,
                         "launchdJob=unknown\ndaemonPid=unknown\nbtmDaemon=unknown\nbtmApp=unknown\n")
        stub = 'sudo() { case "$2" in launchctl) return 113 ;; sfltool) printf "partial\\n"; return 1 ;; esac; }\npgrep() { return 1; }\n'
        self.assertEqual(self.run_action("services", stub=stub).stdout,
                         "launchdJob=absent\ndaemonPid=none\nbtmDaemon=unknown\nbtmApp=unknown\n", "a dump that fails part way is unknown")
        stub = 'sudo() { case "$2" in launchctl) return 113 ;; sfltool) ;; esac; }\npgrep() { return 1; }\n'
        self.assertEqual(self.run_action("services", stub=stub).stdout,
                         "launchdJob=absent\ndaemonPid=none\nbtmDaemon=unknown\nbtmApp=unknown\n", "an empty dump is no measurement")

    def state_root(self, journal, find="ok", replay=0, root="present"):
        listing = '"/Library/Application Support/WGEX/journal.log" "/Library/Application Support/WGEX/journal.json"'
        stub = ('sudo() {\n  case "$2" in\n'
                f'    /bin/sh) {"echo " + root if root else "return 1"} ;;\n'
                f'    find) {"printf %s\\\\n " + listing if find == "ok" else "return 1"} ;;\n'
                f'    perl) printf "%s\\n" {shlex.quote(journal)}; return {replay} ;;\n'
                '  esac\n}\n')
        result = self.run_action("state-root", stub=stub)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def reduced(self, journal, **kw):
        return json.loads(self.state_root(journal, **kw).splitlines()[3].split("=", 1)[1])

    def test_state_root_lists_file_names_and_reduces_the_replayed_journal_in_the_pipe(self):
        purged = json.dumps(dict(schemaVersion=2, generation=7, journalSequence=3, pendingSecretDeletions=[], entries=[], resources=[],
                                 lastGoodAddresses={}, settings=dict(lockdown=False, allowLAN=True, captiveWindowSeconds=300, notifications=True),
                                 pfPolicy=dict(disconnected={}), uninstall=dict(completed=True, purgeState=True, finished=["admission"])))
        lines = self.state_root(purged).splitlines()
        self.assertEqual(lines[:3], ["root=present", "file=journal.json", "file=journal.log"])
        self.assertEqual(len(lines), 4)
        reduced = json.loads(lines[3].split("=", 1)[1])
        self.assertEqual(reduced, {"entries": "array:0", "generation": "integer", "generation.value": 7, "journalSequence": "integer",
                                   "lastGoodAddresses": "object:0", "pendingSecretDeletions": "array:0", "pfPolicy": "object:1",
                                   "pfPolicy.disconnected": "true", "resources": "array:0", "schemaVersion": "integer", "schemaVersion.value": 2,
                                   "settings": "object:4", "settings.default": "true", "uninstall": "object:3", "uninstall.completed": "true",
                                   "uninstall.purgeState": "true"})
        self.assertTrue(U.journal_marker_only(reduced), "the guest's reduction of a purged document passes the row's check")
        self.assertIn('sudo -n perl "$stage/journal-replay.pl" "$root" 2>/dev/null | perl', block("state-root"), "the replay never reaches a file")

    def test_state_root_reduces_values_to_fixed_booleans_and_types_without_leaking_them(self):
        # REV-M03-T15 item 2: the values a purge must reset are judged in the guest; only the generation number leaves.
        def reduce(**document):
            base = dict(schemaVersion=2, generation=7, journalSequence=3, settings=dict(lockdown=False, allowLAN=True,
                        captiveWindowSeconds=300, notifications=True), pfPolicy=dict(disconnected={}),
                        uninstall=dict(completed=True, purgeState=True, finished=[]))
            base.update(document)
            return self.reduced(json.dumps({key: value for key, value in base.items() if value is not None}))
        settings = dict(lockdown=False, allowLAN=True, captiveWindowSeconds=300, notifications=True)
        self.assertEqual(reduce()["settings.default"], "true")
        for change in (dict(lockdown=True), dict(captiveWindowSeconds=60), dict(lockdown=0), dict(captiveWindowSeconds="300"),
                       dict(captiveWindowSeconds=300.5), dict(extra=1), dict(notifications=None)):
            with self.subTest(settings=change):
                value = dict(settings, **change)
                reduced = reduce(settings={key: item for key, item in value.items() if item is not None})
                self.assertEqual(reduced["settings.default"], "false")
        connected = reduce(pfPolicy=dict(connected=dict(interfaceName="utun4", endpoints=["192.0.2.1"])))
        self.assertEqual((connected["pfPolicy"], connected["pfPolicy.disconnected"]), ("object:1", "false"))
        self.assertEqual(reduce(pfPolicy=dict(disconnected=dict(x=1)))["pfPolicy.disconnected"], "false")
        self.assertEqual(reduce(pfPolicy="disconnected")["pfPolicy.disconnected"], "false")
        missing = reduce(generation=None)
        self.assertNotIn("generation", missing)
        self.assertNotIn("generation.value", missing)
        text = reduce(generation="7", schemaVersion=2.5)
        self.assertEqual((text["generation"], text["schemaVersion"]), ("string", "number"))
        self.assertNotIn("generation.value", text)
        self.assertNotIn("schemaVersion.value", text)
        flags = reduce(uninstall=dict(completed=1, purgeState="true"))
        self.assertEqual((flags["uninstall.completed"], flags["uninstall.purgeState"]), ("false", "false"), "only JSON true is true")
        secret = self.state_root(json.dumps(dict(schemaVersion=2, generation=7, pfToken="secret-token", intent=dict(profileID="P"),
                                                 lastGoodAddresses={"utun4": ["10.77.0.2"]})))
        for value in ("secret-token", "10.77.0.2", "utun4", "profileID"):
            self.assertNotIn(value, secret)
        reduced = json.loads(secret.splitlines()[3].split("=", 1)[1])
        self.assertEqual((reduced["pfToken"], reduced["intent"], reduced["lastGoodAddresses"]), ("string", "object:1", "object:1"))

    def test_state_root_reads_that_fail_are_unknown_or_unreadable_not_absent(self):
        # REV-M03-T15 item 3: sudo failing, find failing and a replay that fails (even after printing) are measurements.
        good = json.dumps(dict(schemaVersion=2, generation=7))
        self.assertEqual(self.state_root(good, root=None), "root=unknown\n")
        self.assertEqual(self.state_root(good, root="absent"), "root=absent\n")
        self.assertEqual(self.state_root(good, root="other"), "root=other\n")
        self.assertEqual(self.state_root(good, find="fail").splitlines()[:2], ["root=present", "files=unknown"])
        self.assertEqual(self.state_root(good, replay=1).splitlines()[-1], "journal=unreadable", "the last line wins in the field reader")
        self.assertEqual(self.state_root("not json").splitlines()[-1], "journal=unreadable")
        live = LIVE.Session("fixture", {}, runner=replay.RecordedRunner())
        for kw, key in ((dict(replay=1), "journal"), (dict(find="fail"), "files")):
            with self.subTest(read=key):
                text = self.state_root(good, **kw).encode()
                with patch.object(live, "uninstall_action", lambda *a, **k: text):
                    fields = live.uninstall_fields("state-root")
                self.assertEqual(fields[key], "unknown" if key == "files" else "unreadable")
                self.assertEqual(failed(edit(observation(), ["uninstall", "variants", "purge", "after", "stateRoot", key], fields[key])),
                                 ["purge:stateRootMarkerOnly"])

    def test_services_read_launchd_the_daemon_and_both_btm_items(self):
        btm = ("                 UUID: A\\n                 Name: WGEX\\n                 Type: app (0x2)\\n"
               "          Disposition: [enabled, allowed, not notified] (0x3)\\n           Identifier: 2.com.magrathean.WGEXApp.dev\\n"
               "                 UUID: B\\n                 Name: WGEXDaemon\\n                 Type: daemon (0x10)\\n"
               "          Disposition: [disabled, allowed, not notified] (0x2)\\n           Identifier: 16.com.magrathean.WGEXApp.dev.daemon\\n")
        stub = f'sudo() {{ case "$2" in launchctl) return 113 ;; sfltool) printf "{btm}" ;; esac; }}\npgrep() {{ return 1; }}\n'
        self.assertEqual(self.run_action("services", stub=stub).stdout,
                         "launchdJob=absent\ndaemonPid=none\nbtmDaemon=[disabled, allowed, not notified]\nbtmApp=[enabled, allowed, not notified]\n")
        other = "                 UUID: C\\n                 Type: app (0x2)\\n          Disposition: [enabled] (0x1)\\n           Identifier: 2.other\\n"
        stub = f'sudo() {{ case "$2" in launchctl) return 0 ;; sfltool) printf "{other}" ;; esac; }}\npgrep() {{ echo 7869; }}\n'
        self.assertEqual(self.run_action("services", stub=stub).stdout, "launchdJob=present\ndaemonPid=7869\nbtmDaemon=absent\nbtmApp=absent\n")

    def test_refuse_runs_each_request_as_the_console_user_and_prints_codes_and_error_names_only(self):
        stub = '''id() { if [[ "$1" == -un ]]; then echo labuser; else echo 501; fi; }
stat() { echo labuser; }
sudo() {
  case "$*" in
    *" up "*) printf '{"error":"uninstallFailed"}\\n'; return 19 ;;
    *" on-demand "*) printf '{"error":"uninstallFailed"}\\n'; return 19 ;;
    *" down "*) printf '{"phase":"idle","result":"stopped"}\\n'; return 0 ;;
  esac
}
'''
        result = self.run_action("refuse", PROFILE, stub=stub)
        self.assertEqual(result.stdout, "up=19 uninstallFailed\nonDemand=19 uninstallFailed\ndown=0 none\n", result.stderr)
        self.assertNotEqual(self.run_action("refuse", "not-a-uuid", stub=stub).returncode, 0)
        self.assertEqual(self.run_action("refuse", PROFILE, stub=stub.replace("stat() { echo labuser; }", "stat() { echo root; }")).returncode, 1)

    def test_the_script_has_every_action_the_driver_calls_and_never_touches_the_network_setup(self):
        text = SCRIPT.read_text()
        driver = (ROOT / "Tools/lab/verdict-live.py").read_text()
        called = set(re.findall(r'uninstall_(?:action|fields)\("([a-z-]+)"', driver))
        self.assertEqual(called, {"cli-start", "cli-result", "cleanup", "services", "pf", "profiles", "status", "state-root", "app-state",
                                  "stop-app", "secure-install", "stamp", "start-failure", "restart-daemon", "refuse"})
        for action in called:
            self.assertRegex(text, rf"(?m)^  {action}\)$")
        self.assertNotRegex(text, r"\b(?:ifconfig|route |networksetup|pfctl -[A-Za-z]*[fFeEdk]|scutil --set)")
        self.assertNotIn("lab-login", text)
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)]).returncode, 0)


class Guest:
    """The guest for the driver tests: the daemon, the tunnel, the app and its sheet, BTM and the CLI's run."""

    def __init__(self):
        self.connected = False
        self.daemon, self.uninstalled, self.secure, self.app = True, False, "verified", True
        self.login_item, self.offer, self.final = False, False, False
        self.cli = None
        self.cli_polls = 0
        self.quit_works, self.unregister_hangs, self.offer_shown = True, False, True
        self.tunnel_after_install = True
        self.restarted = False
        self.purge = False
        self.calls = []

    def services(self):
        enabled = "[enabled, allowed, not notified]"
        disabled = "[disabled, allowed, not notified]"
        return (f"launchdJob={'present' if self.daemon else 'absent'}\ndaemonPid={7869 if self.daemon else 'none'}\n"
                f"btmDaemon={enabled if self.daemon else disabled}\nbtmApp={enabled if self.login_item else disabled}\n")

    def action(self, action, *args, **kw):
        self.calls.append((action,) + args)
        if action == "cli-start":
            self.cli, self.purge = "running", args[0] == "purge"
            return b"startedAt=1794445891.512\n"
        if action == "cli-result":
            self.cli_polls += 1
            if self.cli == "stuck" or self.cli_polls < 3:
                return b"rc=running\n"
            self.uninstalled, self.connected, self.cli = True, False, "done"
            return f'rc=0\nreply={{"purge":{str(self.purge).lower()},"replyReadable":true,"result":"uninstalled"}}\n'.encode()
        if action == "services":
            return self.services().encode()
        if action == "pf":
            rules = 46 if self.connected else 0
            return f"anchorListed=true\nanchorRules={rules}\nanchorTables={1 if rules else 0}\nanchorNested=0\nreferences={1 if rules else 0}\n".encode()
        if action == "profiles":
            return b"appProfiles=1\nprofilePresent=true\n"
        if action == "status":
            purge = "true" if self.purge else "false"
            return (f'rc=0\nstatus={{"phase":"idle","protection":"unprotected","uninstall":{{"completed":true,"pendingStep":null,'
                    f'"purgeState":{purge}}}}}\nuninstallLine=uninstall: completed{" (purge)" if self.purge else ""}; the service is '
                    'uninstalled; open WGEX to finish removing the background service and login item\n').encode()
        if action == "refuse":
            return b"up=19 uninstallFailed\nonDemand=19 uninstallFailed\ndown=0 none\n"
        if action == "state-root":
            journal = FIXTURE["pass"]["uninstall"]["variants"]["purge"]["after" if self.uninstalled else "before"]["stateRoot"]["journal"]
            return f'root=present\nfile=journal.json\nfile=journal.log\njournal={json.dumps(journal)}\n'.encode()
        if action == "app-state":
            return b"app=running\n" if self.app else b"app=exited\n"
        if action == "stop-app":
            self.app = False
            return b"stopped=term\n"
        if action == "secure-install":
            return f"secureInstall={self.secure}\n".encode()
        if action == "stamp":
            return b"2026-11-12 01:20:00\n"
        if action == "start-failure":
            return b"start failed, type: HostAdapterError case: unboundInterfaces\nstart failed at step: createEngine\n"
        if action == "restart-daemon":
            self.restarted = True
            return b""
        if action == "cleanup":
            return b""
        raise AssertionError("unexpected guest action " + action)

    def dump(self, window, identifier=None, **kw):
        lines = ["AXWindow | name=WGEX | value= | desc= | id= | pos=0,0 size=800x600 en="]
        shown = {LIVE.UNINSTALL_CONFIRM: self.offer and not self.final, LIVE.UNINSTALL_QUIT: self.final,
                 LIVE.SECURE_INSTALL_ACTION: self.secure != "verified", LIVE.REGISTER_SERVICE: not self.daemon}
        lines += [f"AXButton | name= | value= | desc= | id={key} | pos=10,10 size=20x20 en=true" for key, on in shown.items() if on]
        return "\n".join(lines) + "\n"

    def click(self, identifier, window="1", timeout=None):
        self.calls.append(("click", identifier))
        if identifier == LIVE.UNINSTALL_CONFIRM:
            if not self.unregister_hangs:
                self.daemon, self.login_item, self.final = False, False, True
        elif identifier == LIVE.UNINSTALL_QUIT:
            if self.quit_works:
                self.app = False
        elif identifier == LIVE.REGISTER_SERVICE:
            self.daemon, self.secure = True, "needsAttention(wrappingKeyUnavailable)"
        elif identifier == LIVE.SECURE_INSTALL_ACTION:
            self.secure, self.uninstalled = "verified", False

    def lab(self, *args, **kw):
        self.calls.append(("lab",) + args)
        if args[:4] == ("gui", "run", "open", "-a"):
            self.app = True
            self.offer = self.uninstalled and self.offer_shown and self.daemon
            self.final = False
        return b""

    def await_status(self, protection, timeout=60, phase=None):
        self.calls.append(("await", protection))
        if protection == "protected" and not self.connected:
            raise LIVE.PollDeadline("status protection=protected deadline after 90 s")

    def connect(self, profile):
        self.calls.append(("connect",))
        if self.connected:
            raise ValueError("missing or ambiguous accessible control")  # the toolbar offers Disconnect (live attempt 1)
        self.connected = not self.uninstalled and (self.tunnel_after_install or self.restarted or not self.calls_since_install())

    def calls_since_install(self):
        return any(call == ("click", LIVE.SECURE_INSTALL_ACTION) for call in self.calls)


def driven(guest, **overrides):
    live = LIVE.Session("fixture", {}, runner=replay.RecordedRunner())
    live.profile_ids["full4"] = PROFILE
    records, observed = [], []

    def generate(state, role=None, **kw):
        guest.calls.append(("generate", state, role))
        return dict(state=state, role=role)

    def observe():
        observed.append(guest.connected)
        return dict(status=dict(phase="active", protection="protected") if guest.connected else dict(phase="idle", protection="unprotected"),
                    referenceCount=1 if guest.connected else 0, routes=ROUTES_PROTECTED if guest.connected else ROUTES_BASELINE,
                    dns=DNS_PROTECTED if guest.connected else DNS_BASELINE, ifconfig=IFCONFIG_PROTECTED if guest.connected else "",
                    rules="block drop quick all\n" if guest.connected else "")

    def set_login(identity):
        guest.calls.append(("login",))
        guest.login_item = True

    def guest_action(action, *args, **kw):
        guest.calls.append(("verdict-actions", action))
        if action == "down":
            guest.connected = False
        return b'{"secureInstall":"verified"}\n'

    patches = dict(uninstall_action=guest.action, guest_file=lambda data, name: guest.calls.append(("stage", name)),
                   select_profile=lambda profile: None, set_startup_login=set_login, connect=guest.connect, await_status=guest.await_status,
                   generate=generate, observe=observe, quit_app=lambda: guest.calls.append(("quit",)) or setattr(guest, "app", False),
                   read_dump=guest.dump, click_id=guest.click, lab=guest.lab, open_settings=lambda: "1",
                   select_settings_tab=lambda *a: guest.calls.append(("tab",) + a[1:]), close_settings=lambda *a: None,
                   console_approval=lambda deadline: guest.calls.append(("approve",)) or True,
                   console_finish=lambda: dict(result="typed", startedAt="2026-11-12T01:11:37Z"), guest_action=guest_action,
                   status=lambda *a, **kw: dict(phase="active", protection="protected") if guest.connected else dict(phase="failed", protection="blocked"),
                   pause=lambda seconds: setattr(live.runner, "clock", live.runner.clock + seconds))
    patches.update(overrides)
    baseline = observe()
    observed.clear()
    with patch.multiple(live, **patches):
        records = live.uninstall_row("full4", baseline)
    return live, records


def names(guest, kind):
    return [call for call in guest.calls if call[0] == kind]


class DriverTests(unittest.TestCase):
    def test_both_variants_run_in_order_and_the_recorded_observation_passes_every_check_without_a_workaround(self):
        guest = Guest()
        live, records = driven(guest)
        order = [call[1] if call[0] in ("cli-start", "click") else call[0] for call in guest.calls
                 if call[0] in ("login", "connect", "quit", "cli-start", "click", "refuse", "state-root")]
        self.assertEqual(order, ["login", "connect", "quit", "keep", "refuse", LIVE.UNINSTALL_CONFIRM, LIVE.UNINSTALL_QUIT,
                                 LIVE.REGISTER_SERVICE, LIVE.SECURE_INSTALL_ACTION, "connect",
                                 "state-root", "quit", "purge", "refuse", "state-root", LIVE.UNINSTALL_CONFIRM, LIVE.UNINSTALL_QUIT,
                                 LIVE.REGISTER_SERVICE, LIVE.SECURE_INSTALL_ACTION, "connect"])
        self.assertEqual([(r["state"], r["role"]) for r in records],
                         [("protected", "beforeUninstall:keep"), ("unprotected", "afterUninstall:keep"), ("protected", "afterFreshInstall:keep"),
                          ("protected", "beforeUninstall:purge"), ("unprotected", "afterUninstall:purge"), ("protected", "afterFreshInstall:purge")])
        observation = live.row_observation
        self.assertEqual(observation["uninstall"]["variants"]["keep"]["cli"]["reply"]["result"], "uninstalled")
        self.assertEqual(sorted(n for n, c in checks(observation).items() if not c["met"]), [])
        self.assertEqual(len(names(guest, "cleanup")), 2, "the CLI's work directory goes after each run")
        self.assertEqual(names(guest, "restart-daemon"), [])
        self.assertEqual(names(guest, "stop-app"), [])
        purge = observation["uninstall"]["variants"]["purge"]
        self.assertEqual((purge["before"]["stateRoot"]["journal"]["generation.value"], purge["after"]["stateRoot"]["journal"]["generation.value"]),
                         (4, 5), "the generation while protected, then after the purge (the fence)")
        self.assertNotIn("stateRoot", observation["uninstall"]["variants"]["keep"]["before"])

    def test_a_cli_that_never_finishes_is_a_named_gap_after_the_console_step(self):
        guest = Guest()
        original = guest.action

        def stuck(action, *args, **kw):
            if action == "cli-result":
                guest.calls.append((action,))
                return b"rc=running\n"
            return original(action, *args, **kw)
        with self.assertRaises(LIVE.RowFailure) as raised:
            driven(guest, uninstall_action=stuck)
        self.assertEqual(raised.exception.reason, "uninstallApprovalMissing")
        self.assertEqual(len(names(guest, "approve")), 1, "the console types once, when the dialog shows")

    def test_an_app_that_never_offers_the_finish_is_a_named_gap(self):
        guest = Guest()
        guest.offer_shown = False
        with self.assertRaises(LIVE.RowFailure) as raised:
            driven(guest)
        self.assertEqual(raised.exception.reason, "uninstallFinishNotOffered")

    def test_a_quit_the_sheet_blocks_is_recorded_and_the_driver_stops_the_app(self):
        guest = Guest()
        guest.quit_works = False
        live, _ = driven(guest)
        quit_item = live.row_observation["uninstall"]["variants"]["keep"]["finish"]["quit"]
        self.assertEqual(quit_item, dict(pressed=True, exited=False, driverStopped="term"))
        self.assertIn("keep:finalQuitEndsApp", [n for n, c in checks(live.row_observation).items() if not c["met"]])

    def test_a_failed_app_state_read_never_counts_as_the_quit_ending_the_app(self):
        # REV-M03-T15 r3 item 1: the guest script's own output for a pgrep failure (exit 3) after a Quit that did end the app.
        guest = Guest()
        original = guest.action
        app_state = GuestActionTests().run_action("app-state", stub="pgrep() { return 3; }\n").stdout.encode()
        stop_app = GuestActionTests().run_action("stop-app", stub="pgrep() { return 3; }\n").stdout.encode()
        self.assertEqual((app_state, stop_app), (b"app=unknown\n", b"stopped=unknown\n"))

        def failing(action, *args, **kw):
            if action in ("app-state", "stop-app"):
                guest.calls.append((action,) + args)
                return app_state if action == "app-state" else stop_app
            return original(action, *args, **kw)
        live, _ = driven(guest, uninstall_action=failing)
        for variant in ("keep", "purge"):
            with self.subTest(variant=variant):
                quit_item = live.row_observation["uninstall"]["variants"][variant]["finish"]["quit"]
                self.assertEqual(quit_item, dict(pressed=True, exited=False, driverStopped="unknown"))
        self.assertGreater(len(names(guest, "app-state")), 2, "the driver polls until the bound, never taking unknown as exited")
        failing_checks = sorted(n for n, c in checks(live.row_observation).items() if not c["met"])
        self.assertEqual(failing_checks, ["keep:finalQuitEndsApp", "purge:finalQuitEndsApp"])

    def test_an_unregister_that_hangs_records_no_final_screen_and_fails_the_hang_watch(self):
        guest = Guest()
        guest.unregister_hangs = True
        live, _ = driven(guest)
        finish = live.row_observation["uninstall"]["variants"]["keep"]["finish"]
        self.assertFalse(finish["finalScreen"])
        self.assertGreaterEqual(finish["seconds"], U.FINISH_BOUND_SECONDS)
        self.assertFalse(finish["quit"]["pressed"], "no Quit press without the final screen")
        failing = [n for n, c in checks(live.row_observation).items() if not c["met"]]
        self.assertIn("keep:finishDidNotHang", failing)
        self.assertIn("keep:serviceRemovedByApp", failing)

    def test_a_tunnel_that_does_not_start_after_the_fresh_install_is_recorded_then_the_daemon_restart_lets_the_row_go_on(self):
        guest = Guest()
        guest.tunnel_after_install = False
        live, records = driven(guest)
        tunnel = live.row_observation["uninstall"]["variants"]["keep"]["freshInstall"]["tunnel"]
        self.assertFalse(tunnel["protected"])
        self.assertTrue(tunnel["driverRestartedDaemon"])
        self.assertTrue(tunnel["protectedAfterDaemonRestart"])
        self.assertEqual(tunnel["startFailure"], ["start failed, type: HostAdapterError case: unboundInterfaces", "start failed at step: createEngine"])
        self.assertEqual(len(names(guest, "restart-daemon")), 1, "once: the restart sticks for the purge variant in this fake")
        self.assertEqual(len(records), 6)
        self.assertIn("keep:tunnelStartsAfterFreshInstall", [n for n, c in checks(live.row_observation).items() if not c["met"]])


class RunTests(unittest.TestCase):
    def test_run_dispatches_the_row_with_the_pre_tunnel_baseline_and_trails_the_unprotected_control(self):
        seen = {}

        def row(self, profile, baseline):
            seen.update(profile=profile, status=baseline["status"])
            self.row_observation["uninstall"] = copy.deepcopy(FIXTURE["pass"]["uninstall"])
            self.connect(profile)
            self.await_status("protected")
            return [self.generate("protected", role="beforeUninstall:keep")]
        with patch.object(LIVE.Session, "uninstall_row", row):
            runner, result = run8.run_row("UNINSTALL", run8.Run8Runner())
        self.assertEqual(seen, dict(profile="full4", status=dict(phase="idle", protection="unprotected")),
                         "the baseline is read before any connect (connect false)")
        self.assertEqual(result["tailControlPosition"], "trail")
        self.assertEqual(result["states"][-1]["role"], "unprotectedTail")
        self.assertEqual([c["name"] for c in result["checks"] if not c["met"]], [])
        self.assertTrue(result["rowCompleted"])


if __name__ == "__main__":
    unittest.main()
