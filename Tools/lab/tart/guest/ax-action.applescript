-- Act on one element found by accessibility identifier and role (M1-10j). Arguments
-- are data, never AppleScript source: process name, window index, identifier,
-- mode, then for press or confirm the fallback point X Y and the role, for
-- press-only the role, and optionally a child label (SwiftUI radio buttons carry
-- no identifier; their group does). Role "-" matches the identifier alone; any
-- other role must also match, so a container repeating the identifier is skipped.
-- Identifier "-" (press modes only, never with role "-"; gui.sh enforces both) matches the role alone, so a
-- control without an identifier is found by its title inside the first container of that role (M1-10m, guest run
-- 8d: the Settings toolbar buttons carry no identifier; "- press X Y AXToolbar Service" presses the Service tab).
-- With frame=X,Y,WxH in place of the title (M1-10r, guest run 8f), identifier "-" presses the element of that role with
-- exactly that frame: a startup radio button, which exposes only its group's label, chosen by position by the driver.
-- In place of the child label, frame=X,Y,WxH makes the element also match that
-- exact position and size (M1-10k fix pass 1, F3): a dump showing the
-- identifier twice presses the element the driver remembered, not the first.
-- press, confirm: perform AXPress or AXConfirm on the element, or on the child
-- whose description, name or title is the label; when the element is missing
-- or refuses the action, click at X Y. The driver passes a point only after
-- checking the element frame lies inside the window frame of its dump.
-- press-only: AXPress with no point and never a click (the off-screen path).
-- An AXPopUpButton is pressed ignoring application responses (its menu blocks
-- the reply) and never clicked after an Apple Event timeout.
-- scroll: AXScrollToVisible on the element, else set the vertical scroll bar of
-- the nearest enclosing scroll area so the element is centred. That area is
-- found among the walk's own positional parent references (M1-10l fix pass 1,
-- F2): each level of findChildren holds its element by index from "window N",
-- and as the walk unwinds from the match the nearest AXScrollArea is kept;
-- never AXParent or a list System Events returns, whose references name the
-- window by its title. Its scroll bar and document are taken by index too, and
-- every geometry read and the scroll bar write sit in try blocks (scroll=none).
-- Scroll never activates, raises or focuses a window, presses or clicks (M1-10k):
-- when neither is available it returns scroll=none with nothing changed, so the
-- window order the driver dumped is the order it re-dumps.
-- The result line names the path: path=element, path=element-timeout,
-- path=coordinate for the press modes; press-only, which has no point to click, reports why it failed (M1-10m,
-- guest run 8d, where both cases read path=none): path=miss when the walk (or the child label) found no element,
-- path=error number=N when AXPress on the found element threw AppleScript error N;
-- scroll=action, scroll=bar, scroll=missing (no such element in the window) or
-- scroll=none (no scroll available) for scroll.
-- Delivery stamp (M1-10o fix pass 2, F1; guest run 8e: the End press command took 4.93 s, mostly this helper's own
-- walk): a press that acts (path=element, element-timeout or coordinate) is preceded by the line
-- pressedAt=<guest epoch seconds with milliseconds>, read immediately before AXPress, AXConfirm or the fallback click
-- (stampNow), after the walk; the driver measures GUI timing from it. No line when the clock read fails; the driver
-- then falls back to the instant it issued the command.
-- Targeted lookup (M1-10l, guest run 8d): no `entire contents`, whose
-- specifiers name the window by a title the main window rewrites every second.
-- Every mode walks the window depth first from "window N", building each
-- element reference by index (UI element i of ... of window N), one try block
-- per element, at most WALK_DEPTH_LIMIT levels and WALK_ELEMENT_BUDGET elements
-- (as ax-dump.applescript), and stops at the first element matching identifier,
-- role and frame: a press never needs the whole tree, and one failing or
-- mutating subtree never hides the rest.
property WALK_DEPTH_LIMIT : 16
property WALK_ELEMENT_BUDGET : 4000
-- walkMatched, not a comparison of walkFound with missing value, says whether the walk matched: comparing a
-- reference makes AppleScript get it, outside any try block (F3). walkArea: the nearest AXScrollArea ancestor of the
-- match, looked up only when wantArea (scroll mode).
global walkCount, walkDone, walkFound, walkMatched, wantArea, walkArea, walkAreaFound, ident, roleName, frameX, frameY, frameW, frameH

on run argv
  set appName to item 1 of argv
  set winIdx to (item 2 of argv) as integer
  set ident to item 3 of argv
  set modeName to item 4 of argv
  set childLabel to ""
  set roleName to "-"
  set pointX to missing value
  set pointY to missing value
  set frameX to missing value
  set frameY to missing value
  set frameW to missing value
  set frameH to missing value
  if modeName is "press" or modeName is "confirm" then
    if (count of argv) < 7 then error "press and confirm need X Y ROLE" number 2
    set pointX to (item 5 of argv) as integer
    set pointY to (item 6 of argv) as integer
    set roleName to item 7 of argv
    if (count of argv) > 7 then set childLabel to item 8 of argv
  else if modeName is "press-only" then
    if (count of argv) < 5 then error "press-only needs ROLE" number 2
    set roleName to item 5 of argv
    if (count of argv) > 5 then set childLabel to item 6 of argv
  else if modeName is "scroll" then
    if (count of argv) > 4 then set childLabel to item 5 of argv
  else
    error "mode must be press, confirm, press-only or scroll" number 2
  end if
  if childLabel starts with "frame=" then
    set savedDelimiters to AppleScript's text item delimiters
    set AppleScript's text item delimiters to {"=", ",", "x"}
    set frameParts to text items of childLabel
    set AppleScript's text item delimiters to savedDelimiters
    if (count of frameParts) is not 5 then error "frame must be frame=X,Y,WxH" number 2
    set frameX to (item 2 of frameParts) as integer
    set frameY to (item 3 of frameParts) as integer
    set frameW to (item 4 of frameParts) as integer
    set frameH to (item 5 of frameParts) as integer
    set childLabel to ""
  end if
  if modeName is "confirm" then
    set actionName to "AXConfirm"
  else
    set actionName to "AXPress"
  end if
  set walkCount to 0
  set walkDone to false
  set walkFound to missing value
  set walkMatched to false
  set wantArea to modeName is "scroll"
  set walkArea to missing value
  set walkAreaFound to false
  tell application "System Events" to tell process appName
    -- No try here: a window that does not exist still fails the whole helper (gui.sh prints ax-action=failed).
    set childCount to count of UI elements of window winIdx
    set windowRef to a reference to window winIdx
  end tell
  my findChildren(windowRef, childCount, 1)
  set found to walkFound
  set haveFound to walkMatched
  set scrollArea to walkArea
  set haveArea to walkAreaFound
  tell application "System Events" to tell process appName
    if haveFound and childLabel is not "" then
      set groupElement to found
      set haveFound to false
      set labelCount to 0
      try
        set labelCount to count of UI elements of groupElement
      end try
      repeat with i from 1 to labelCount
        set c to a reference to UI element i of groupElement
        set labels to {}
        try
          set end of labels to (description of c as text)
        end try
        try
          set end of labels to (name of c as text)
        end try
        try
          set end of labels to (title of c as text)
        end try
        if labels contains childLabel then
          set found to c
          set haveFound to true
          exit repeat
        end if
      end repeat
      -- The group is the child's parent, so the nearest candidate scroll area.
      if haveFound and wantArea then
        try
          if (role of groupElement as text) is "AXScrollArea" then
            set scrollArea to groupElement
            set haveArea to true
          end if
        end try
      end if
    end if
    if modeName is "scroll" then
      if not haveFound then return "scroll=missing"
      try
        perform action "AXScrollToVisible" of found
        return "scroll=action"
      end try
      if not haveArea then return "scroll=none"
      set areaCount to 0
      try
        set areaCount to count of UI elements of scrollArea
      end try
      set haveBar to false
      set haveDocument to false
      repeat with i from 1 to areaCount
        set c to a reference to UI element i of scrollArea
        try
          if (role of c as text) is "AXScrollBar" then
            if (value of attribute "AXOrientation" of c as text) is "AXVerticalOrientation" then
              set barElement to c
              set haveBar to true
            end if
          else if not haveDocument then
            set documentElement to c
            set haveDocument to true
          end if
        end try
      end repeat
      if not (haveBar and haveDocument) then return "scroll=none"
      try
        set elementTop to item 2 of (position of found as list)
        set elementHeight to item 2 of (size of found as list)
        set areaHeight to item 2 of (size of scrollArea as list)
        set documentTop to item 2 of (position of documentElement as list)
        set documentHeight to item 2 of (size of documentElement as list)
        if documentHeight is less than or equal to areaHeight then return "scroll=none"
        set fraction to ((elementTop - documentTop) - ((areaHeight - elementHeight) / 2)) / (documentHeight - areaHeight)
        if fraction < 0 then set fraction to 0
        if fraction > 1 then set fraction to 1
        set value of attribute "AXValue" of barElement to fraction
        return "scroll=bar"
      end try
      return "scroll=none"
    end if
    set pressError to missing value
    set pressStamp to ""
    if haveFound then
      set foundRole to ""
      try
        set foundRole to role of found as text
      end try
      if foundRole is "AXPopUpButton" then
        try
          set pressStamp to my stampNow()
          ignoring application responses
            perform action actionName of found
          end ignoring
          return my pressResult("path=element", pressStamp)
        on error errorText number errorNumber
          if errorNumber is -1712 then return my pressResult("path=element-timeout", pressStamp)
          set pressError to errorNumber
        end try
      else
        try
          set pressStamp to my stampNow()
          perform action actionName of found
          return my pressResult("path=element", pressStamp)
        on error errorText number errorNumber
          set pressError to errorNumber
        end try
      end if
    end if
  end tell
  if pointX is missing value then
    if pressError is missing value then return "path=miss"
    return "path=error number=" & ((pressError as integer) as text)
  end if
  set pressStamp to my stampNow()
  tell application "System Events" to click at {pointX, pointY}
  return my pressResult("path=coordinate", pressStamp)
end run

-- The guest clock now, epoch seconds with milliseconds (as verdict-actions.sh now()), or "" when it cannot be read.
-- Called outside any tell block, so the shell runs in this script, not in System Events.
on stampNow()
  try
    return do shell script "/usr/bin/perl -MTime::HiRes=time -e 'printf q(%.3f), time'"
  end try
  return ""
end stampNow

-- A press report: pressedAt=<stamp> on its own line before the path, or the path alone without a stamp.
on pressResult(pathText, pressStamp)
  if pressStamp is "" then return pathText
  return "pressedAt=" & pressStamp & linefeed & pathText
end pressResult

-- Children 1..childCount of parentRef (walkDepth levels below the window), depth first; walkFound is the first match.
-- With wantArea, each level whose subtree held the match reads its own element's role as the walk unwinds, nearest
-- first, and the first AXScrollArea becomes walkArea: the positional parent references on the recursion stack (F2).
on findChildren(parentRef, childCount, walkDepth)
  repeat with i from 1 to childCount
    if walkDone then return
    if walkCount is greater than or equal to WALK_ELEMENT_BUDGET then
      set walkDone to true
      return
    end if
    set walkCount to walkCount + 1
    tell application "System Events" to set e to a reference to UI element i of parentRef
    if my elementMatches(e) then
      set walkFound to e
      set walkMatched to true
      set walkDone to true
      return
    end if
    if walkDepth is less than WALK_DEPTH_LIMIT then
      set kids to 0
      try
        tell application "System Events" to set kids to count of UI elements of e
      end try
      if kids > 0 then
        my findChildren(e, kids, walkDepth + 1)
        if walkMatched and wantArea and not walkAreaFound then
          try
            tell application "System Events" to set areaRole to role of e as text
            if areaRole is "AXScrollArea" then
              set walkArea to e
              set walkAreaFound to true
            end if
          end try
        end if
      end if
    end if
  end repeat
end findChildren

-- Identifier ("-": any, M1-10m), then role ("-": any), then the exact frame when frame=X,Y,WxH was given (F3).
on elementMatches(e)
  tell application "System Events"
    try
      if ident is "-" or (value of attribute "AXIdentifier" of e as text) is ident then
        if roleName is "-" or (role of e as text) is roleName then
          set frameMatches to true
          if frameX is not missing value then
            set p to position of e
            set z to size of e
            set frameMatches to ((item 1 of p) as integer) = frameX and ((item 2 of p) as integer) = frameY and ((item 1 of z) as integer) = frameW and ((item 2 of z) as integer) = frameH
          end if
          return frameMatches
        end if
      end if
    end try
  end tell
  return false
end elementMatches
