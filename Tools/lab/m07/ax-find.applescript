-- SPDX-License-Identifier: MIT
-- M07-T08b: find one element of a WGEX window by its accessibility identifier, whatever its role, run in the guest
-- console session only (gui run). ax-dump.applescript's targeted walk prints only listed roles, so an element made with
-- .accessibilityElement(children: .ignore) or .combine (the setup sheet's Background service row, live run 3) or a text
-- editor's scroll area never yields a line there; and System Events' "description" answers the role description, not
-- the label. This walk reads the raw attributes instead.
-- Arguments (data): APP WINDOW IDENTIFIER [contains NEEDLE]. The same depth-first walk as ax-dump.applescript
-- (UI element i of ... of window N, one try per element, WALK_DEPTH_LIMIT and WALK_ELEMENT_BUDGET), stopping at the
-- first element whose AXIdentifier is IDENTIFIER. Output, one line, tab separated:
--   ax-find=found  role=R  value=V  label=AXDescription  title=AXTitle  enabled=E  frame=x,y,w,h  text=T  attrs=A
--   [contains=yes|no]
-- With "focus" as the fourth argument (M07-T16), the element (or, for a scroll area, its first text area) is given the
-- keyboard focus through AXFocused before the line is printed, which then ends in focus=set or focus=failed.
-- or "ax-find=missing", then the walk summary line. text is the one reading every caller uses (live run 4: SwiftUI
-- buttons and combined or ignored rows answer no AXTitle or AXDescription in the guest, and System Events' description
-- falls back to the role description): the first non-empty of AXValue, AXTitle, AXDescription, AXValueDescription,
-- AXHelp, else the same of its descendants up to three levels down. attrs names the element's attributes (names only,
-- for diagnosis). The value and text of a text area, a secure field, a private key row or the configuration text are
-- never printed ("<omitted>"); with "contains", only whether the element's text contains NEEDLE is printed.
property WALK_DEPTH_LIMIT : 16
property WALK_ELEMENT_BUDGET : 4000
global walkCount, walkErrors, walkTruncated, targetIdent, foundRef

on run argv
	set appName to item 1 of argv
	set winIdx to (item 2 of argv) as integer
	set targetIdent to item 3 of argv
	set needle to ""
	set containsMode to false
	set focusMode to false
	if (count of argv) > 4 and item 4 of argv is "contains" then
		set containsMode to true
		set needle to item 5 of argv
	end if
	if (count of argv) > 3 and item 4 of argv is "focus" then set focusMode to true
	set walkCount to 0
	set walkErrors to 0
	set walkTruncated to 0
	set foundRef to missing value
	tell application "System Events" to tell process appName
		set childCount to count of UI elements of window winIdx
		set windowRef to a reference to window winIdx
	end tell
	my walkChildren(windowRef, childCount, 1)
	set summary to "ax-walk: elements=" & walkCount & " truncated=" & walkTruncated & " errors=" & walkErrors
	if foundRef is missing value then return "ax-find=missing" & linefeed & summary
	set e to foundRef
	set r to my attr(e, "AXRole")
	set sr to my attr(e, "AXSubrole")
	set v to my attr(e, "AXValue")
	set secret to (r is "AXTextArea" or sr is "AXSecureTextField" or targetIdent contains "rivateKey" or targetIdent contains "configurationText")
	if secret or containsMode then set v to "<omitted>"
	set en to my attr(e, "AXEnabled")
	set frame to ""
	try
		tell application "System Events" to set p to position of e
		tell application "System Events" to set s to size of e
		set frame to (((item 1 of p) as integer) as text) & "," & (((item 2 of p) as integer) as text) & "," & (((item 1 of s) as integer) as text) & "," & (((item 2 of s) as integer) as text)
	end try
	set t to "<omitted>"
	if not (secret or containsMode) then set t to my textOf(e, 0)
	set names to ""
	try
		tell application "System Events" to set attrNames to name of every attribute of e
		set AppleScript's text item delimiters to ","
		set names to attrNames as text
		set AppleScript's text item delimiters to ""
	end try
	set out to "ax-find=found" & tab & "role=" & r & tab & "value=" & my oneLine(v) & tab & "label=" & my oneLine(my attr(e, "AXDescription")) & tab & "title=" & my oneLine(my attr(e, "AXTitle")) & tab & "enabled=" & en & tab & "frame=" & frame & tab & "text=" & my oneLine(my firstLine(t)) & tab & "attrs=" & my oneLine(names)
	if containsMode then
		set hit to "no"
		if (my textOf(e, 0)) contains needle then set hit to "yes"
		set out to out & tab & "contains=" & hit
	end if
	if focusMode then
		set focusResult to "failed"
		try
			set target to e
			if r is "AXScrollArea" then
				tell application "System Events" to set target to (first UI element of e whose role is "AXTextArea")
			end if
			tell application "System Events" to set value of attribute "AXFocused" of target to true
			set focusResult to "set"
		end try
		set out to out & tab & "focus=" & focusResult
	end if
	return out & linefeed & summary
end run

on attr(e, attrName)
	try
		tell application "System Events" to set x to value of attribute attrName of e
		if x is missing value then return ""
		return x as text
	on error
		return ""
	end try
end attr

-- The element's own text (the first non-empty of AXValue, AXTitle, AXDescription, AXValueDescription, AXHelp), else its
-- descendants' texts (three levels), joined by linefeeds.
on ownText(e)
	repeat with attrName in {"AXValue", "AXTitle", "AXDescription", "AXValueDescription", "AXHelp"}
		set x to my attr(e, attrName as text)
		if x is not "" then return x
	end repeat
	return ""
end ownText

-- The first non-empty line of a text, or "".
on firstLine(t)
	repeat with p in paragraphs of t
		if (p as text) is not "" then return p as text
	end repeat
	return ""
end firstLine

on textOf(e, depth)
	set own to my ownText(e)
	if own is not "" then return own
	if depth is greater than or equal to 3 then return ""
	set joined to ""
	try
		tell application "System Events" to set kids to count of UI elements of e
		repeat with i from 1 to kids
			tell application "System Events" to set c to a reference to UI element i of e
			set joined to joined & (my textOf(c, depth + 1)) & linefeed
		end repeat
	end try
	return joined
end textOf

on oneLine(t)
	set AppleScript's text item delimiters to {linefeed, return, tab}
	set parts to text items of t
	set AppleScript's text item delimiters to " "
	set flat to parts as text
	set AppleScript's text item delimiters to ""
	return flat
end oneLine

on walkChildren(parentRef, childCount, walkDepth)
	repeat with i from 1 to childCount
		if walkCount is greater than or equal to WALK_ELEMENT_BUDGET then
			set walkTruncated to 1
			return
		end if
		set walkCount to walkCount + 1
		tell application "System Events" to set e to a reference to UI element i of parentRef
		set ident to ""
		try
			tell application "System Events" to set ident to value of attribute "AXIdentifier" of e as text
		end try
		considering case
			if ident is targetIdent then
				set foundRef to e
				return
			end if
		end considering
		set kids to 0
		try
			tell application "System Events" to set kids to count of UI elements of e
		on error
			set walkErrors to walkErrors + 1
		end try
		if kids > 0 then
			if walkDepth is less than WALK_DEPTH_LIMIT then
				my walkChildren(e, kids, walkDepth + 1)
				if foundRef is not missing value then return
			else
				set walkTruncated to 1
			end if
		end if
	end repeat
end walkChildren
