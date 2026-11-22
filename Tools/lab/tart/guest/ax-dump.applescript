-- Dump the accessibility tree of one window: role, name, value, description,
-- position, size and enabled flag, one element per line, after a first
-- AXWindow line carrying the window title (the WGEX main window titles itself
-- with the selected profile name) and the window frame, the bounds the driver
-- checks before any coordinate click (M1-10j). Arguments: process name and
-- window index.
-- Run through asu.sh so System Events can reach the console session; the
-- calling binary needs the Accessibility and AppleEvents TCC rows seeded by
-- seed-tcc.sh.
-- M1-10l (guest run 8d): no `entire contents`. System Events answered that with
-- a short list most of the time, and the specifiers it returns name the window
-- by its title, which the main window rewrites every second ("last handshake
-- N s ago"). The walk below builds every element reference itself, by index
-- from "window N" (UI element i of UI element j of window N), depth first in
-- the same pre-order, with one try block per element: an element or subtree
-- that fails or mutates mid-read is counted and skipped, the rest is still
-- read. The walk stops at WALK_DEPTH_LIMIT levels below the window and after
-- WALK_ELEMENT_BUDGET elements. The last line is the walk summary
-- "ax-walk: elements=N truncated=0|1 errors=M" (truncated=1: the depth limit or
-- the budget left elements unread; errors: elements or subtrees that could not
-- be read), so the driver can tell a complete read from a partial one.
-- M1-10o (guest run 8e: a complete walk of the connected main window took
-- 142-161 s, about 1 s per element, longer than one element search's bound):
-- an optional third argument, a wgex accessibility identifier, selects the
-- targeted walk the driver's element searches use. The same walk in the same
-- order, but each element costs one AXIdentifier read (plus the child count)
-- instead of a full line; only an element carrying the identifier is described,
-- and the walk stops at the first one that yields a line. The output is the
-- AXWindow line, that line, and the summary with " target=found" or
-- " target=missing" appended. Without the argument the full dump is unchanged.
property WALK_DEPTH_LIMIT : 16
property WALK_ELEMENT_BUDGET : 4000
global walkCount, walkErrors, walkTruncated, walkOut, targetIdent, targetFound

on run argv
  set appName to item 1 of argv
  set winIdx to (item 2 of argv) as integer
  set walkCount to 0
  set walkErrors to 0
  set walkTruncated to 0
  set targetIdent to ""
  if (count of argv) > 2 then set targetIdent to item 3 of argv
  set targetFound to false
  tell application "System Events" to tell process appName
    set t to ""
    try
      set t to name of window winIdx
    end try
    set frame to ""
    try
      set wp to position of window winIdx
      set ws to size of window winIdx
      set frame to " pos=" & (item 1 of wp) & "," & (item 2 of wp) & " size=" & (item 1 of ws) & "x" & (item 2 of ws)
    end try
    -- No try here: a window that does not exist still fails the whole helper (gui.sh prints ax-dump=failed).
    set childCount to count of UI elements of window winIdx
    set windowRef to a reference to window winIdx
  end tell
  set walkOut to "AXWindow | name=" & t & " | value= | desc= | id= |" & frame & linefeed
  my walkChildren(windowRef, childCount, 1)
  if targetIdent is not "" then
    set targetWord to "missing"
    if targetFound then set targetWord to "found"
    return walkOut & "ax-walk: elements=" & walkCount & " truncated=" & walkTruncated & " errors=" & walkErrors & " target=" & targetWord
  end if
  return walkOut & "ax-walk: elements=" & walkCount & " truncated=" & walkTruncated & " errors=" & walkErrors
end run

-- Children 1..childCount of parentRef, which sit walkDepth levels below the window.
on walkChildren(parentRef, childCount, walkDepth)
  repeat with i from 1 to childCount
    if walkCount is greater than or equal to WALK_ELEMENT_BUDGET then
      set walkTruncated to 1
      return
    end if
    set walkCount to walkCount + 1
    tell application "System Events" to set e to a reference to UI element i of parentRef
    if targetIdent is "" then
      my describeElement(e)
    else
      my matchElement(e)
      if targetFound then return
    end if
    set kids to 0
    try
      tell application "System Events" to set kids to count of UI elements of e
    on error
      set walkErrors to walkErrors + 1
    end try
    if kids > 0 then
      if walkDepth is less than WALK_DEPTH_LIMIT then
        my walkChildren(e, kids, walkDepth + 1)
        if targetFound then return
      else
        set walkTruncated to 1
      end if
    end if
  end repeat
end walkChildren

-- Targeted walk (M1-10o): describe the element only when it carries the
-- identifier; the walk stops once such an element has produced its line (an
-- element of an unlisted role prints nothing and the walk goes on). An element
-- without an identifier attribute is not a walk error. Identifiers compare
-- case-sensitively, as the driver's parsers do.
on matchElement(e)
  set found to ""
  try
    tell application "System Events" to set found to value of attribute "AXIdentifier" of e as text
  end try
  set carries to false
  considering case
    set carries to (found is targetIdent)
  end considering
  if carries then
    set lineMark to length of walkOut
    my describeElement(e)
    if length of walkOut is greater than lineMark then set targetFound to true
  end if
end matchElement

-- One dump line for an element of a listed role, in the format of every earlier dump.
on describeElement(e)
  tell application "System Events"
    try
      set r to role of e
    on error
      set walkErrors to walkErrors + 1
      return
    end try
    if r is in {"AXButton", "AXRadioButton", "AXRadioGroup", "AXGroup", "AXCheckBox", "AXStaticText", "AXTextField", "AXPopUpButton", "AXLink", "AXMenuButton", "AXSwitch", "AXTab", "AXRow", "AXCell", "AXToolbar", "AXTabGroup"} then
      try
        set n to ""
        try
          set n to name of e
        end try
        set v to ""
        try
          set v to value of e as text
        end try
        set d to ""
        try
          set d to description of e
        end try
        set ident to ""
        try
          set ident to value of attribute "AXIdentifier" of e as text
        end try
        if r is "AXTextField" then set v to "<omitted>"
        set p to position of e
        set s to size of e
        set en to ""
        try
          set en to enabled of e
        end try
        set walkOut to walkOut & r & " | name=" & n & " | value=" & v & " | desc=" & d & " | id=" & ident & " | pos=" & (item 1 of p) & "," & (item 2 of p) & " size=" & (item 1 of s) & "x" & (item 2 of s) & " en=" & en & linefeed
      on error
        set walkErrors to walkErrors + 1
      end try
    end if
  end tell
end describeElement
