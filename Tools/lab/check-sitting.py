#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Order check for the cutover sitting pack (M04-T01): check-sitting.py FILE.

Exits 0 only when FILE keeps the order the maintainer follows once:
  * the first `## ` heading is `## Rollback`;
  * `### E1` to `### E4` precede `### C1`, and `### C1` precedes the cutover start line;
  * `### S1` to `### S3` sit between that start line and the cutover confirm line, `### S4` to `### S8` follow it;
  * every E, C and S heading is followed, before the next heading, by a `Command:` line and then an `Expected:` line,
    each with content;
  * procedure points earlier reviews fixed stay in place: the Rollback's `### After cutover confirm` runs `chk disarm`
    before `chk abort`, and its `### Disarm not verified` runs `chk bootout`; S4 and S5 each run `chk s123` at least twice (S1 to S3 after each network change); S6 has two
    Wi-Fi cycles, with `chk phasewatch --until active` after the first and `chk phasewatch --hold idle` after the second;
  * the checks VER-M04-SITTING tightened stay in place: C2 has one `chk status` command line that expects
    `cutover.state=armed`, `protection=protected`, `phase=active` and `operationInFlight=false` (RUNBOOK trial flow
    step 2), and S6 waits with `chk phasewatch --until idle` after the include cycle's `--until active` and before the
    exclude cycle turns Wi-Fi off, so the hold never starts while the tunnel is still stopping.

Tokens: a heading is a line `#{1,6} <title>` outside a fenced block, and an E, C or S heading is
`### <E|C|S><number> <title>`; a fence opens and closes on a line whose first non-blank characters are three backticks;
a command is `chk <words>` inside a fence, at the start of a line (after blanks) or after `;` or `&&`, ending at a word
boundary (a `-` continues the word); the start and confirm lines hold the commands `chk cutover-start` and
`chk cutover-confirm` (the helper runs `"$cli" cutover start|confirm` and fails on a non-zero exit or an error reply),
each exactly once; an expectation is `--expect KEY=VALUE`, the pair optionally in single or double quotes, on the
same line as `chk status`; a Wi-Fi cycle is a line outside a fence that says `turn Wi-Fi off` and later `turn Wi-Fi back on`
or `turn it back on`, in any case.
The pack names no `M04-rc<N>` tag other than the helper's `CANDIDATE_TAG` (Tools/lab/sitting/checks.py); a token is
`M04-rc` and digits, not followed by a word character or `-`.
Standard library only; run with `python3 -I`. Reads the file; touches nothing.
"""
import os
import re
import sys

REQUIRED = ["E1", "E2", "E3", "E4", "C1", "C2", "C3"] + ["S%d" % n for n in range(1, 9)]
HEADING = re.compile(r"^###\s+([ECS]\d+)(?:\s+\S.*)?$")
ANY_HEADING = re.compile(r"^#{1,6}\s")


def command(words):
    """A command at the start of a line or after `;` or `&&`, ending at a word boundary."""
    return re.compile(r"(?:^|;|&&)\s*chk\s+" + words + r"(?![\w-])")


START = command(r"cutover-start")
CONFIRM = command(r"cutover-confirm")
DISARM = command(r"disarm")
ABORT = command(r"abort")
BOOTOUT = command(r"bootout")
S123 = command(r"s123")
UNTIL_ACTIVE = command(r"phasewatch\s+--until\s+active")
HOLD_IDLE = command(r"phasewatch\s+--hold\s+idle")
UNTIL_IDLE = command(r"phasewatch\s+--until\s+idle")
STATUS = command(r"status")
ARMED_EXPECTS = ("cutover.state=armed", "protection=protected", "phase=active", "operationInFlight=false")
WIFI_CYCLE = re.compile(r"turn wi-fi off\b.*\bturn (wi-fi|it) back on\b", re.I)
LABEL = re.compile(r"^\s*(Command|Expected):(.*)$")


def scan(lines):
    """Return (first_h2, headings, starts, confirms, bodies) with 1-based line numbers; fences are skipped for headings."""
    first_h2 = None
    headings = {}
    duplicates = []
    starts, confirms = [], []
    bodies = {}
    current = None
    in_fence = False
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            if current is not None:
                bodies[current].append((number, line, True))
            continue
        if in_fence:
            starts += [number] * len(START.findall(line))
            confirms += [number] * len(CONFIRM.findall(line))
        if not in_fence and ANY_HEADING.match(line):
            if first_h2 is None and line.startswith("## "):
                first_h2 = line[3:].strip()
            match = HEADING.match(line)
            if match:
                name = match.group(1)
                if name in headings:
                    duplicates.append(name)
                else:
                    headings[name] = number
                current = (name, number)
                bodies[current] = []
            else:
                current = None
            continue
        if current is not None:
            bodies[current].append((number, line, in_fence))
    return first_h2, headings, duplicates, starts, confirms, bodies


def label_problems(name, body):
    """Command: then Expected:, each with text after the colon or a non-blank line before the next label."""
    marks = []
    for index, (number, line, in_fence) in enumerate(body):
        match = None if in_fence else LABEL.match(line)
        if match:
            marks.append((match.group(1), index, match.group(2).strip()))
    problems = []
    kinds = [kind for kind, _, _ in marks]
    for kind in ("Command", "Expected"):
        if kind not in kinds:
            problems.append("%s has no `%s:` line" % (name, kind))
    if problems:
        return problems
    if kinds.index("Command") > kinds.index("Expected"):
        problems.append("%s has `Expected:` before `Command:`" % name)
    for position, (kind, index, inline) in enumerate(marks):
        end = marks[position + 1][1] if position + 1 < len(marks) else len(body)
        if not inline and not any(text.strip() and not text.lstrip().startswith("```") for _, text, _ in body[index + 1:end]):
            problems.append("%s has an empty `%s:`" % (name, kind))
    return problems


def sections(lines):
    """Every heading outside a fence: {title: [(number, line, in_fence), ...]} up to the next heading of any level."""
    found, current, in_fence = {}, None, False
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence and ANY_HEADING.match(line):
            current = line.lstrip("#").strip()
            found.setdefault(current, [])
            continue
        if current is not None:
            found[current].append((number, line, in_fence))
    return found


def commands(body, pattern):
    return [number for number, line, in_fence in body if in_fence for _ in pattern.findall(line)]


def expects(line, pair):
    """`--expect KEY=VALUE` on LINE, bare or in quotes, ending at a blank, a quote or the end of the line."""
    return re.search(r"--expect\s+(['\"]?)" + re.escape(pair) + r"\1(?=\s|;|&|$)", line) is not None


def procedure_problems(lines):
    """The procedure points earlier reviews fixed (round 5 item 7)."""
    found = sections(lines)
    by_name = {}
    for title, body in found.items():
        match = HEADING.match("### " + title)
        if match:
            by_name.setdefault(match.group(1), body)
    problems = []
    after = found.get("After cutover confirm")
    if after is None:
        problems.append("the Rollback has no `### After cutover confirm`")
    else:
        disarms, aborts = commands(after, DISARM), commands(after, ABORT)
        if not disarms:
            problems.append("Rollback `After cutover confirm` has no `chk disarm` command (verified disarm)")
        elif not aborts or min(aborts) < min(disarms):
            problems.append("Rollback `After cutover confirm` must run `chk disarm` before `chk abort`")
    unverified = found.get("Disarm not verified")
    if unverified is None:
        problems.append("the Rollback has no `### Disarm not verified`")
    elif not commands(unverified, BOOTOUT):
        problems.append("Rollback `Disarm not verified` has no `chk bootout` command (the failed-disarm branch)")
    for name in ("S4", "S5"):
        runs = len(commands(by_name.get(name, []), S123))
        if runs < 2:
            problems.append("%s runs `chk s123` %d time(s); S1 to S3 must repeat after each of its two changes" % (
                name, runs))
    s6 = by_name.get("S6", [])
    cycles = [number for number, line, in_fence in s6 if not in_fence and WIFI_CYCLE.search(line)]
    if len(cycles) < 2:
        problems.append("S6 has %d Wi-Fi cycle(s); the include and exclude cycles both turn Wi-Fi off and back on"
                        % len(cycles))
    else:
        if not any(cycles[0] < number < cycles[1] for number in commands(s6, UNTIL_ACTIVE)):
            problems.append("S6 has no `chk phasewatch --until active` after its include cycle")
        if not any(number > cycles[1] for number in commands(s6, HOLD_IDLE)):
            problems.append("S6 has no `chk phasewatch --hold idle` after its exclude cycle")
        actives = [number for number in commands(s6, UNTIL_ACTIVE) if cycles[0] < number < cycles[1]]
        if actives and not any(min(actives) < number < cycles[1] for number in commands(s6, UNTIL_IDLE)):
            problems.append("S6 has no `chk phasewatch --until idle` between its include check and the exclude "
                            "cycle (wait for idle before Wi-Fi goes off)")
    c2 = [(number, line) for number, line, in_fence in by_name.get("C2", []) if in_fence and STATUS.search(line)]
    if not any(all(expects(line, pair) for pair in ARMED_EXPECTS) for _, line in c2):
        problems.append("C2 has no `chk status` line expecting %s" % ", ".join(ARMED_EXPECTS))
    return problems


def helper_tag():
    """The candidate tag constant in Tools/lab/sitting/checks.py (CANDIDATE_TAG = "M04-rcN")."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sitting", "checks.py")
    with open(path, encoding="utf-8") as handle:
        found = re.search(r'^CANDIDATE_TAG = "(M04-rc\d*)"', handle.read(), re.M)
    return found.group(1) if found else None


def tag_problems(text, tag):
    """Every `M04-rc<N>` token in the pack must equal the helper's constant."""
    if tag is None:
        return ["the helper holds no CANDIDATE_TAG constant"]
    names = sorted(set(re.findall(r"M04-rc\d*(?![\w-])", text)))
    return ["the pack names %s but the helper's CANDIDATE_TAG is %s" % (name, tag) for name in names if name != tag]


def check(text, tag=None):
    tag = tag if tag is not None else helper_tag()
    lines = text.splitlines()
    first_h2, headings, duplicates, starts, confirms, bodies = scan(lines)
    problems = []
    if first_h2 != "Rollback":
        problems.append("the first `## ` heading must be `## Rollback`, found %r" % first_h2)
    for name in duplicates:
        problems.append("%s heading appears more than once" % name)
    for name in REQUIRED:
        if name not in headings:
            problems.append("missing heading %s" % name)
    if len(starts) != 1:
        problems.append("expected exactly one `chk cutover-start` command line, found %d" % len(starts))
    if len(confirms) != 1:
        problems.append("expected exactly one `chk cutover-confirm` command line, found %d" % len(confirms))
    if problems:
        return problems
    start, confirm = starts[0], confirms[0]
    at = headings
    for name in ("E1", "E2", "E3", "E4"):
        if at[name] > at["C1"]:
            problems.append("%s must precede C1" % name)
    for earlier, later in (("E1", "E2"), ("E2", "E3"), ("E3", "E4")):
        if at[earlier] > at[later]:
            problems.append("%s must precede %s" % (earlier, later))
    if at["C1"] > start:
        problems.append("C1 must precede the `cutover start` line")
    if not at["C1"] < at["C2"] < at["C3"]:
        problems.append("C1, C2 and C3 must come in that order")
    if start > confirm:
        problems.append("the `cutover start` line must precede the `cutover confirm` line")
    for name in ("S1", "S2", "S3"):
        if at[name] < start:
            problems.append("%s must follow the `cutover start` line" % name)
        if at[name] > confirm:
            problems.append("%s must precede the `cutover confirm` line" % name)
    for name in ("S4", "S5", "S6", "S7", "S8"):
        if at[name] < confirm:
            problems.append("%s must follow the `cutover confirm` line" % name)
    for first, second in (("S1", "S2"), ("S2", "S3"), ("S4", "S5"), ("S5", "S6"), ("S6", "S7"), ("S7", "S8")):
        if at[first] > at[second]:
            problems.append("%s must precede %s" % (first, second))
    for (name, _), body in sorted(bodies.items(), key=lambda item: item[0][1]):
        problems.extend(label_problems(name, body))
    problems.extend(procedure_problems(lines))
    problems.extend(tag_problems(text, tag))
    return problems


def main(argv):
    if len(argv) != 2:
        print("usage: check-sitting.py FILE", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as error:
        print("check-sitting: cannot read %s: %s" % (argv[1], error), file=sys.stderr)
        return 2
    problems = check(text)
    for problem in problems:
        print("check-sitting: " + problem, file=sys.stderr)
    if problems:
        return 1
    print("check-sitting: order ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
