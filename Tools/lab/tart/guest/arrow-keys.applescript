-- Focus one element by accessibility identifier (a scroll area's outline or
-- table child when it wraps one), then press one arrow key a bounded number of
-- times. SwiftUI sidebar rows ignore clicks and AXSelected but follow arrow
-- keys. Arguments are data, never AppleScript source: process name, window
-- index, identifier, up or down, count (0 to 64), and optionally the word
-- fallback. With fallback, a missing identifier (run 6: SwiftUI exposes no
-- wgex.main.profiles element) takes the keyboard path from the window: the
-- outline, table or list that holds a wgex.main.tunnel.<UUID> row (AXParent
-- walk), else the window's first outline, table or list. The result line names
-- the path that pressed the keys: path=identifier or path=window (L17).
on run argv
  set appName to item 1 of argv
  set winIdx to (item 2 of argv) as integer
  set ident to item 3 of argv
  set dir to item 4 of argv
  set pressCount to (item 5 of argv) as integer
  set allowFallback to false
  if (count of argv) > 5 then
    if item 6 of argv is "fallback" then
      set allowFallback to true
    else
      error "sixth argument must be fallback" number 2
    end if
  end if
  if dir is "up" then
    set keyNumber to 126
  else if dir is "down" then
    set keyNumber to 125
  else
    error "direction must be up or down" number 2
  end if
  if pressCount < 0 or pressCount > 64 then error "count must be 0 to 64" number 2
  set listRoles to {"AXOutline", "AXTable", "AXList"}
  tell application "System Events" to tell process appName
    set frontmost to true
    set els to entire contents of window winIdx
    set found to missing value
    set pathName to "identifier"
    repeat with e in els
      try
        if (value of attribute "AXIdentifier" of e as text) is ident then
          set found to contents of e
          exit repeat
        end if
      end try
    end repeat
    if found is missing value then
      if not allowFallback then error "identifier not found" number 3
      set pathName to "window"
      repeat with e in els
        try
          if (value of attribute "AXIdentifier" of e as text) starts with "wgex.main.tunnel." then
            set p to contents of e
            repeat 8 times
              set p to value of attribute "AXParent" of p
              if role of p is in listRoles then
                set found to p
                exit repeat
              end if
            end repeat
          end if
        end try
        if found is not missing value then exit repeat
      end repeat
      if found is missing value then
        repeat with e in els
          try
            if role of e is in listRoles then
              set found to contents of e
              exit repeat
            end if
          end try
        end repeat
      end if
      if found is missing value then error "identifier not found and no profile list in the window" number 3
    end if
    try
      if role of found is "AXScrollArea" then
        repeat with c in (UI elements of found)
          if role of c is in listRoles then
            set found to contents of c
            exit repeat
          end if
        end repeat
      end if
    end try
    try
      set value of attribute "AXFocused" of found to true
    end try
    repeat pressCount times
      key code keyNumber
      delay 0.15
    end repeat
  end tell
  return "path=" & pathName
end run
