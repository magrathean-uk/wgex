-- Click at guest screen coordinates (points, origin top-left). Arguments: x y.
on run argv
  tell application "System Events" to click at {(item 1 of argv) as integer, (item 2 of argv) as integer}
end run
