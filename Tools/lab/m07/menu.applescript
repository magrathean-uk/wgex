-- SPDX-License-Identifier: MIT
-- M07-T08b: the WGEX menu bar item's NSMenu (MacTextMenuController), run in the guest console session only (gui run).
-- Arguments are data: "read" opens the menu, prints one line per item (item=<title><tab>mark=<mark><tab>enabled=<bool>)
-- and closes it with Escape; "click" TITLE opens it and clicks the item whose title is exactly TITLE.
-- An open NSMenu holds System Events' reply to the opening click for several seconds, so the click is sent ignoring
-- application responses and the guest's own System Events is restarted before the menu is read.
on run argv
	set mode to item 1 of argv
	tell application "System Events" to tell process "WGEX"
		ignoring application responses
			click menu bar item 1 of menu bar 2
		end ignoring
	end tell
	delay 0.5
	do shell script "/usr/bin/killall 'System Events' >/dev/null 2>&1 || true"
	delay 1
	tell application "System Events" to tell process "WGEX"
		set m to menu 1 of menu bar item 1 of menu bar 2
		if mode is "click" then
			click menu item (item 2 of argv) of m
			return "menu=clicked"
		end if
		set out to ""
		repeat with i in menu items of m
			set t to ""
			try
				set t to name of i
			end try
			if t is missing value then set t to ""
			set mark to ""
			try
				set mark to value of attribute "AXMenuItemMarkChar" of i
			end try
			if mark is missing value then set mark to ""
			set en to "unknown"
			try
				set en to (enabled of i) as text
			end try
			set out to out & "item=" & t & tab & "mark=" & mark & tab & "enabled=" & en & linefeed
		end repeat
		key code 53
		return out & "menu=read"
	end tell
end run
