# SPDX-License-Identifier: MIT
"""M03-T07 phase B: select_profile reads the window title from a targeted walk first. M5.3-09's full walk of the connected
main window took 224 s, then ran past the 360 s SSH deadline twice under host load; after Import and Connect the title already
names the profile, so no full dump is read. A title that does not name it keeps the full-dump path for the sidebar rows."""
import unittest

import test_gui_element as element

LIVE = element.LIVE
ID = "00000000-0000-4000-8000-000000000108"
NAME = "wgex-lab-full4"
ACTION = ("AXButton | name=missing value | value= | desc=Disconnect | id=" + LIVE.MAIN_ACTION
          + " | pos=900,40 size=60x30 en=true\n")


def window(title):
    return f"AXWindow | name={title} | value= | desc= | id= | pos=0,30 size=1024x752\n"


def session(*dumps):
    runner, live = element.session(*dumps)
    live.guest_action = lambda action, *args, **kw: ID.encode() if action == "profile-id" else b""
    live.pause = lambda seconds: None
    return runner, live


class SelectProfileTitleTests(unittest.TestCase):
    def test_a_title_naming_the_profile_needs_no_full_dump(self):
        runner, live = session(window(NAME + LIVE.TITLE_STATUS_SEPARATOR + "Connected") + ACTION)
        live.select_profile("full4")
        self.assertEqual(element.gui(runner, "dump"), [["dump", "WGEX", "1", LIVE.MAIN_ACTION]])
        self.assertEqual(live.profile_ids["full4"], ID)
        self.assertEqual(live.ledger[-1]["titleForm"], "statusSuffix")
        self.assertEqual(live.ledger[-1]["arrowKeys"], [])

    def test_another_title_still_reads_the_full_dump_and_names_a_missing_row(self):
        runner, live = session(window("wgex-lab-other") + ACTION)
        with self.assertRaises(LIVE.RowFailure) as raised:
            live.select_profile("full4")
        dumps = element.gui(runner, "dump")
        self.assertEqual(dumps[0], ["dump", "WGEX", "1", LIVE.MAIN_ACTION])
        self.assertIn(["dump", "WGEX", "1"], dumps[1:])
        self.assertIn("profileSelectionMismatch", str(raised.exception.args))


if __name__ == "__main__":
    unittest.main()
