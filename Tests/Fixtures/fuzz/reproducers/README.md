# Fuzz reproducers

M1-14 campaigns run through `just test fuzz`. Each target gets a 60-second smoke by default;
`WGEX_FUZZ_SECONDS=600 just test fuzz` requests the milestone's ten-minute-per-target campaign.
The optional first `run.sh` argument is seconds per target; the second is a deterministic seed.

Targets: `parser`, `stats`, `endpoint`, `cidr`, `original`, `profile`, `pairing`, `qr`, `redactor`, `zip`.
The original-text oracle performs parse -> exportOriginalWgQuick -> parse, compares all configuration
semantics after normalising per-import identities/references/timestamps, and compares every secret in
borrowed buffers. Other codecs use decode/encode/decode equality; the redactor is checked with the
shared SecretScanner, parser inputs are checked for wiping/public-text leaks, stats reject forbidden
member names, and ZIP output is checked against resource caps. Unmutated seeds are also exercised.

Names are `<target>-<result>-<vector>.bin`. Saved vectors replay after every campaign. A finding,
crash or watchdog hang returns nonzero; vector bytes and keys are never printed. A 50 ms deadline is
retried twice to filter scheduling noise; a two-second watchdog saves a hanging vector. Quantiles
retain at most 100,000 samples per target. Reproducers and seeds use repository fixture identities
only; the mutator inserts invalid key tokens rather than generating cryptographic keys.

ZIP seeds in `../zip/` cover stored and deflate entries with traversal-shaped display names;
entries never touch disk. The `.conf` corpus includes repeated lists and ignored Apple directives.

| File | Status |
|---|---|
| `parser-secret-in-public-original-s7-i904.bin` | Existing fixed regression: key in a trailing comment must be redacted. |

`zip-positive-control-rejected-seed-0.bin` is the deflate positive-control regression:
Compression initialisation resets stream buffers, so source/destination pointers are assigned
after initialisation. This seed must be accepted during replay.
