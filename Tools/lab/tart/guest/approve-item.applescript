-- SPDX-License-Identifier: MIT
-- M03-T11 AUTH-REAL: in System Settings > General > Login Items & Extensions, press WGEX's background-item switch
-- (AXCheckBox, AXIdentifier background-switch-WGEX) only when it reads off. Prints one fixed line:
-- item=<identifier> was=<0|1> pressed=<yes|no>, or item=missing. Never types text.
-- Live run 2: `entire contents` returned 204 elements and none of the switches, so this uses ax-dump.applescript's
-- indexed walk (UI element i of UI element j of window N, depth first, one try per element). AppleScript reserves
-- "before" (live run 1: -2741), so the value read is "wasOn".
property TARGET : "background-switch-WGEX"
property WALK_DEPTH_LIMIT : 16
property WALK_ELEMENT_BUDGET : 4000
global walkCount, found

on run argv
	set walkCount to 0
	set found to missing value
	tell application "System Events"
		if not (exists process "System Settings") then return "item=missing"
		set windowCount to count of windows of process "System Settings"
	end tell
	repeat with w from 1 to windowCount
		tell application "System Events" to tell process "System Settings"
			set childCount to count of UI elements of window w
			set windowRef to a reference to window w
		end tell
		my walkChildren(windowRef, childCount, 1)
		if found is not missing value then exit repeat
	end repeat
	if found is missing value then return "item=missing"
	tell application "System Events"
		set wasOn to (value of found) as integer
		if wasOn is 0 then
			perform action "AXPress" of found
			return "item=" & TARGET & " was=0 pressed=yes"
		end if
	end tell
	return "item=" & TARGET & " was=" & wasOn & " pressed=no"
end run

on walkChildren(parentRef, childCount, walkDepth)
	repeat with i from 1 to childCount
		if walkCount is greater than or equal to WALK_ELEMENT_BUDGET then return
		set walkCount to walkCount + 1
		tell application "System Events" to set e to a reference to UI element i of parentRef
		set ident to ""
		set r to ""
		try
			tell application "System Events" to set ident to value of attribute "AXIdentifier" of e as text
			tell application "System Events" to set r to role of e
		end try
		considering case
			if ident is TARGET and r is "AXCheckBox" then
				set found to e
				return
			end if
		end considering
		set kids to 0
		try
			tell application "System Events" to set kids to count of UI elements of e
		end try
		if kids > 0 and walkDepth is less than WALK_DEPTH_LIMIT then
			my walkChildren(e, kids, walkDepth + 1)
			if found is not missing value then return
		end if
	end repeat
end walkChildren
