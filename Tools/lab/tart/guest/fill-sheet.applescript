-- SPDX-License-Identifier: MIT
-- M03-T11 AUTH-REAL, DEC-034: fill the "Login Items is trying to modify your system settings" sheet on System Settings
-- window 1 (right com.apple.backgroundtaskmanagement.manage-daemons) with the guest administrator's password and press
-- Modify Settings. auth-real.sh settings-sheet-fill runs it as the console user after the driver has identified that
-- sheet; it never runs for SecurityAgent (the WGEX right's sheet is only cancelled).
-- argv: <secret-file> <set|keys>. The password is read from the 0600 file (the helper removes it straight after) and is
-- never returned, logged or put in an error: every outcome is one fixed line,
-- fill=<entered|no-sheet|no-field|unreadable|error> [mode=<set|keys>] [field=<secure|default-focus>] [pressed=<modify|no>].
-- set: AXValue on the sheet's secure text field. keys: synthetic key events into it (or into the sheet's default focus
-- when the field is not in the AX tree). Modify Settings is the first of the sheet's two untitled buttons (Cancel is the
-- last, see settings-sheet-cancel). Variable names avoid AppleScript reserved words (live run 1: -2741 on "before").
property WALK_DEPTH_LIMIT : 10
property WALK_ELEMENT_BUDGET : 400
global walkCount, secureField

on run argv
	set walkCount to 0
	set secureField to missing value
	if (count of argv) is not 2 then return "fill=error"
	set secretPath to item 1 of argv
	set fillMode to item 2 of argv
	if fillMode is not in {"set", "keys"} then return "fill=error"
	try
		set secretText to read (POSIX file secretPath) as «class utf8»
	on error
		return "fill=unreadable"
	end try
	try
		tell application "System Events"
			if not (exists process "System Settings") then return "fill=no-sheet"
			tell process "System Settings"
				if (count of sheets of window 1) is 0 then return "fill=no-sheet"
				set frontmost to true
			end tell
		end tell
		delay 0.5
		tell application "System Events" to set sheetRef to a reference to sheet 1 of window 1 of process "System Settings"
		tell application "System Events" to set childCount to count of UI elements of sheetRef
		my walkChildren(sheetRef, childCount, 1)
	on error
		set secretText to ""
		return "fill=error mode=" & fillMode
	end try
	set fieldKind to "default-focus"
	if secureField is not missing value then set fieldKind to "secure"
	if fillMode is "set" and secureField is missing value then
		set secretText to ""
		return "fill=no-field mode=set"
	end if
	try
		tell application "System Events"
			if secureField is not missing value then
				set focused of secureField to true
				set value of secureField to ""
			end if
			if fillMode is "set" then
				set value of secureField to secretText
			else
				delay 0.3
				keystroke secretText
			end if
		end tell
	on error
		set secretText to ""
		return "fill=error mode=" & fillMode & " field=" & fieldKind
	end try
	set secretText to ""
	delay 0.5
	try
		tell application "System Events" to perform action "AXPress" of first button of group 1 of sheet 1 of window 1 of process "System Settings"
	on error
		return "fill=entered mode=" & fillMode & " field=" & fieldKind & " pressed=no"
	end try
	return "fill=entered mode=" & fillMode & " field=" & fieldKind & " pressed=modify"
end run

on walkChildren(parentRef, childCount, walkDepth)
	repeat with i from 1 to childCount
		if walkCount is greater than or equal to WALK_ELEMENT_BUDGET then return
		set walkCount to walkCount + 1
		tell application "System Events" to set e to a reference to UI element i of parentRef
		set elementRole to ""
		set elementSubrole to ""
		try
			tell application "System Events" to set elementRole to role of e
			tell application "System Events" to set elementSubrole to subrole of e
		end try
		if elementRole is "AXTextField" and elementSubrole is "AXSecureTextField" then
			set secureField to e
			return
		end if
		set kids to 0
		try
			tell application "System Events" to set kids to count of UI elements of e
		end try
		if kids > 0 and walkDepth is less than WALK_DEPTH_LIMIT then
			my walkChildren(e, kids, walkDepth + 1)
			if secureField is not missing value then return
		end if
	end repeat
end walkChildren
