# Keep only a count. Unified-log payloads never enter a regular file or report.
BEGIN { n = 0 }
NR > 1 {
  n++
  printf "events=%d; rawMessagesOmitted=1\n", n > output
  close(output)
}
