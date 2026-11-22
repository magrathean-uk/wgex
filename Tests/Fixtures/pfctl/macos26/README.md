# macOS 26 pfctl transcripts

Captured by the orchestrator in `macos26-wgex`, macOS 26.6.2 (25G83), 27 October 2026.
These are real guest output, including stderr's two ALTQ warning lines. No host pfctl was run.
The duplicate copies formerly directly under `pfctl/` were byte-identical and removed.

| File | Command / meaning |
| --- | --- |
| sw_vers.txt | OS provenance; `sw_vers` |
| info.txt | `pfctl -s info`, before capture; disabled |
| references-before.txt | `pfctl -s References`, no references |
| rules.txt | `pfctl -sr`, stock wildcard anchor |
| rules-verbose.txt | `pfctl -vsr`, stock counters |
| anchors.txt | `pfctl -a com.apple -s Anchors -v`, sibling anchors |
| anchor-wgex.txt | `pfctl -a com.apple/wgex -sr`, empty anchor |
| enable.txt | single `pfctl -E`, `Token : N` |
| references-with-token.txt | `TOKENS:` header and PID / Process Name / TOKEN / TIMESTAMP table |
| release.txt | immediate `pfctl -X N` for that one capture reference |
| references-after.txt | no references after release |
| info-after.txt | abbreviated final status from the original capture |

Refresh with `Tools/lab/tart/guest/pfctl-capture.sh` in the guarded guest only, then copy
the files for review. The script reads state, acquires exactly one reference and releases
it immediately, with an EXIT trap for failure. It never disables pf globally or changes rules.
The numeric token is an ephemeral pf reference, not a cryptographic key. `PFTranscripts`
loads these files; fakes substitute their journalled reference while preserving the format.
For rules comparisons it removes the captured stderr preamble, matching the real executor's
separate stdout/stderr pipes. Token and References parser tests consume the files verbatim.
