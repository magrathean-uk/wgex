-- The app name is data, never interpolated AppleScript source.
on run argv
  set appName to item 1 of argv
  tell application "System Events" to set frontmost of process appName to true
end run
