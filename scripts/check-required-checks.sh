#!/usr/bin/env bash
# check-required-checks.sh: the required-check manifest against the job names.
#
# WHY THIS EXISTS
#
# A required status check is bound to a job by its NAME, and by nothing else.
# The two sides of that binding live apart: the name GitHub requires sits in the
# branch-protection settings, the name a job reports sits in a `name:` key in
# this tree. Nothing connects them but the string.
#
# Measured on 2026-09-10 on pull request #265. A session had renamed a job,
# honestly, because the job had grown:
#
#     "Prose (no em dash)"  ->  "Prose (no em dash, no real names)"
#
#     gh api .../branches/master/protection  requires  "Prose (no em dash)"
#     gh pr checks 265                       reports   "Prose (no em dash, no real names)"
#
# Two names, no match. The required context would never have reported again,
# the enforcement would have vanished without a sound, and the pull request
# showed thirty-two green ticks while it happened. Nothing was silent and
# nothing reported a false success: both sides worked perfectly and simply
# talked past each other, because the channel between them is a string.
#
# The rule, from .claude/rules/claims.md: a binding through a name breaks
# silently the moment either side changes the name. This script is that rule
# made mechanical for one instance of it, the workflow job names.
#
# STATE ON THE DAY IT WAS WRITTEN
#
# There was no drift to repair. Branch protection required 29 contexts, the
# workflow files declared 53 jobs, and each of the 23 contexts that GitHub
# Actions produces from a file in this tree had a job answering to its exact
# name. The gate is prevention against the next rename, not a repair, and that
# is worth saying plainly rather than dressing it up as a fix.
#
# WHAT IT CHECKS
#
#   1. every `workflow` record resolves to a job name declared in
#      .github/workflows/**, matrix names expanded
#   2. the workflow owning such a job can report on a pull request head at all,
#      that is, it triggers on push, pull_request, pull_request_target or
#      workflow_call
#   3. no record classified as produced OUTSIDE the tree is in fact produced by
#      a job inside it, which would mean the classification is wrong and the
#      gate is skipping a check it could have made
#   4. the producer keyword agrees with the app id recorded beside it, so that
#      relabelling a record cannot be used to walk around check 1
#   5. the manifest is internally consistent: known keywords, no duplicate
#      names, and the counts in its header equal what was parsed
#
# WHAT IT CANNOT CHECK, and this matters more than one further tick
#
#   a. whether the 29 names still equal what branch protection requires TODAY.
#      A context added or removed in the GitHub settings is invisible from the
#      tree. Only `--refresh` reads the live API, and running it is a human act.
#   b. whether a declared job is actually REACHED on a pull request. A path
#      filter, an `if:` condition or a skipped `needs:` chain each leave a job
#      declared and unreported.
#   c. check runs made through `workflow_call`. GitHub renames those to
#      "<calling job> / <called job>"; this script resolves the called job's own
#      name. No required context is produced that way today.
#
# HOW THE THREE PRODUCERS ARE TOLD APART
#
# `gh api .../protection` returns an app id beside every required context, and
# it is what separates the classes without guesswork. Measured on 2026-09-10:
#
#     app 15368  github-actions             27 of the 29 contexts
#     app 57789  github-advanced-security     2, "CodeQL" and "gosec"
#
# App 15368 alone does not mean "a job in this tree": the four "Analyze (...)"
# contexts come from the CodeQL DEFAULT SETUP, which is a GitHub Actions
# workflow with no file in this repository. From the API those four look exactly
# like the failure this gate exists to catch, a required Actions context with no
# job of that name. Only a human can tell the two apart, which is why --refresh
# refuses to classify such a context and asks.
#
# MATRIX JOBS
#
# Branch protection sees the EXPANDED names, so this script expands them. A
# matrix whose values are literals in the YAML (all three in this tree are)
# becomes concrete names: `${{ matrix.os }}` in a `name:` yields one name per
# value, and a matrix job with no `name:` yields GitHub's default `<job-id> (v1,
# v2)`. Where an expression survives expansion, because the matrix came from
# `fromJSON` or the name interpolates something other than the matrix, the
# template is kept as a PATTERN and required names are matched against it
# instead of pretending to know the value. `--list` marks those rows `pattern`.
#
# The include/exclude merge implemented here is GitHub's rule in its ordinary
# form: the cartesian product of the plain keys, minus `exclude`, then each
# `include` entry merged into every combination it is compatible with, or
# appended when it is compatible with none. Exotic overrides are not modelled.
#
# python3 with PyYAML does the parsing, and the loader REFUSES duplicate keys:
# a loader that tolerates them answers "can I parse this somehow", and GitHub
# answers a different question. Both the interpreter and the library are already
# relied on by the pin-guard job that runs this script.
#
# Usage:
#   ./scripts/check-required-checks.sh            # the gate (exit 1 on drift)
#   ./scripts/check-required-checks.sh --list     # every resolved job name
#   ./scripts/check-required-checks.sh --refresh  # rewrite the manifest from the API
#
# Exit: 0 clean, 1 drift or an inconsistent manifest, 2 usage error,
#       3 --refresh could not complete (no gh, no permission, a name it will
#         not classify on its own)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

MANIFEST="docs/security/required-checks.txt"
REPO="kamir/m3c-tools"
BRANCH="master"

MODE="${1:-}"
case "$MODE" in
  ""|--list|--refresh) ;;
  *) echo "usage: $0 [--list|--refresh]" >&2; exit 2 ;;
esac

if [ "$MODE" = "--refresh" ] && ! command -v gh >/dev/null 2>&1; then
  echo "FAIL: --refresh needs the gh CLI, and it is not on PATH." >&2
  exit 3
fi

# --refresh reads the live state first, so a failure there costs nothing. The
# `checks` array carries the app id per context; `contexts` carries only names.
LIVE=""
if [ "$MODE" = "--refresh" ]; then
  if ! LIVE="$(gh api "repos/$REPO/branches/$BRANCH/protection" \
                  --jq '.required_status_checks.checks[] | "\(.app_id)\t\(.context)"' 2>&1)"; then
    echo "FAIL: could not read the branch protection of $REPO@$BRANCH." >&2
    echo "      Reading it needs admin rights on the repository." >&2
    printf '%s\n' "$LIVE" >&2
    exit 3
  fi
fi

MANIFEST="$MANIFEST" MODE="$MODE" LIVE="$LIVE" REPO="$REPO" BRANCH="$BRANCH" \
python3 - <<'PY'
import glob, itertools, os, re, sys, yaml

MANIFEST = os.environ["MANIFEST"]
MODE     = os.environ["MODE"]
REPO     = os.environ["REPO"]
BRANCH   = os.environ["BRANCH"]

APP_ACTIONS = "15368"   # github-actions
APP_GHAS    = "57789"   # github-advanced-security (code scanning results)

# Producer keyword -> (app id it must carry, must it resolve to a job here,
# one line of prose). An unknown keyword is a HARD ERROR and never an assumed
# external: a typo must not turn into a silently skipped check.
PRODUCERS = {
    "workflow": (
        APP_ACTIONS, True,
        "a job in .github/workflows/**"),
    "actions-external": (
        APP_ACTIONS, False,
        "a GitHub Actions workflow with no file in this repository, "
        "the CodeQL default setup"),
    "code-scanning": (
        APP_GHAS, False,
        "the GitHub code scanning results check, one context per analysis tool"),
}
PR_CAPABLE = ("push", "pull_request", "pull_request_target", "workflow_call")
EXPR = re.compile(r"\$\{\{.*?\}\}")


class Strict(yaml.SafeLoader):
    pass


def no_duplicate_keys(loader, node, deep=False):
    seen, out = set(), {}
    for k, v in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in seen:
            raise ValueError(f"duplicate key {key!r} at line {k.start_mark.line + 1}")
        seen.add(key)
        out[key] = loader.construct_object(v, deep=deep)
    return out


Strict.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicate_keys)


def triggers(doc):
    # A bare `on:` is parsed as the boolean True by YAML 1.1.
    on = doc.get("on", doc.get(True))
    if isinstance(on, (dict, list)):
        return [str(e) for e in on]
    return [on] if isinstance(on, str) else []


def combinations(matrix):
    """GitHub's matrix expansion in its ordinary form."""
    if not isinstance(matrix, dict):
        return []
    plain = {k: v for k, v in matrix.items()
             if k not in ("include", "exclude") and isinstance(v, list)}
    if plain:
        keys = list(plain)
        combos = [dict(zip(keys, vals))
                  for vals in itertools.product(*(plain[k] for k in keys))]
    else:
        combos = [{}]
    for ex in matrix.get("exclude") or []:
        if isinstance(ex, dict):
            combos = [c for c in combos
                      if not all(c.get(k) == v for k, v in ex.items())]
    inc = [i for i in (matrix.get("include") or []) if isinstance(i, dict)]
    if inc and not plain:
        return inc
    for entry in inc:
        fitting = [c for c in combos
                   if all(c.get(k) == v for k, v in entry.items() if k in c)]
        if fitting:
            for c in fitting:
                c.update(entry)
        else:
            combos.append(dict(entry))
    return combos


def substitute(template, combo):
    def one(m):
        inner = m.group(0)[3:-2].strip()
        if inner.startswith("matrix."):
            field = inner[len("matrix."):].strip()
            if field in combo:
                return str(combo[field])
        return m.group(0)
    return EXPR.sub(one, template)


def resolve():
    """Every check-run name this tree declares: (name, file, job, events, kind)."""
    rows, parse_errors = [], []
    for f in sorted(glob.glob(".github/workflows/*.yml")):
        try:
            with open(f, encoding="utf-8") as fh:
                doc = yaml.load(fh, Strict) or {}
        except Exception as e:                       # noqa: BLE001
            parse_errors.append(f"{f}: {e}")
            continue
        events = triggers(doc)
        for jid, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            matrix = (job.get("strategy") or {}).get("matrix")
            combos = combinations(matrix) if matrix else []
            explicit = job.get("name")
            if not combos:
                nm = str(explicit) if explicit else jid
                rows.append((nm, f, jid, events,
                             "pattern" if EXPR.search(nm) else "literal"))
                continue
            for c in combos:
                nm = (substitute(str(explicit), c) if explicit
                      else f"{jid} ({', '.join(str(v) for v in c.values())})")
                rows.append((nm, f, jid, events,
                             "pattern" if EXPR.search(nm) else "literal"))
    return rows, parse_errors


ROWS, PARSE_ERRORS = resolve()
LITERALS = {r[0]: r for r in ROWS if r[4] == "literal"}
PATTERNS = [r for r in ROWS if r[4] == "pattern"]


def match(name):
    """The job declaring this check name, or None."""
    if name in LITERALS:
        return LITERALS[name]
    for r in PATTERNS:
        rx = "^" + "".join(
            ".*" if p.startswith("${{") else re.escape(p)
            for p in re.split(r"(\$\{\{.*?\}\})", r[0]) if p) + "$"
        if re.match(rx, name):
            return r
    return None


def parse_manifest(path):
    """(lineno, producer, app_id, name, raw) records plus the header counts.

    A '#' starts a comment only at column 0, so a '#' inside a check name can
    never be silently truncated."""
    records, counts = [], None
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            if raw.startswith("#"):
                m = re.match(r"^# records: (\d+) \((.*)\)$", raw)
                if m:
                    per = {}
                    for part in m.group(2).split(","):
                        bits = part.split()
                        if len(bits) == 2 and bits[1].isdigit():
                            per[bits[0]] = int(bits[1])
                    counts = (int(m.group(1)), per)
                continue
            parts = raw.split(None, 2)
            if len(parts) < 3 or not parts[2].strip():
                records.append((lineno, parts[0] if parts else "", "", "", raw))
                continue
            records.append((lineno, parts[0], parts[1], parts[2].strip(), raw))
    return records, counts


# ---------------------------------------------------------------- --list
if MODE == "--list":
    print(f"{len(ROWS)} declared check name(s) from "
          f"{len(set((r[1], r[2]) for r in ROWS))} job(s) in "
          f"{len(set(r[1] for r in ROWS))} workflow file(s), matrix expanded:")
    for name, f, jid, events, kind in sorted(ROWS):
        print(f"  {kind:8} {name}")
        print(f"           {f}  job:{jid}  on:{','.join(events)}")
    for e in PARSE_ERRORS:
        print(f"  FAIL: workflow will not parse: {e}")
    sys.exit(1 if PARSE_ERRORS else 0)

# -------------------------------------------------------------- --refresh
HEADER = """# Required status checks on {branch}, as branch protection requires them.
#
# WHY THIS FILE IS COMMITTED
#
# A required status check is bound to a job by its NAME. Branch protection holds
# one copy of that name, this tree holds the other, and nothing connects them
# but the string. On 2026-09-10 a job was renamed for an honest reason, "Prose
# (no em dash)" became "Prose (no em dash, no real names)", and the required
# context would have stopped reporting for good while the pull request showed
# thirty-two green ticks. A human caught that one.
#
# This file is the tree's copy of the branch-protection side, so that
# scripts/check-required-checks.sh can hold the two names against each other on
# every push and every pull request. A rename is an API change: change the job
# name, this file and the branch-protection setting in the SAME commit.
#
# FORMAT
#
# One record per line: a producer keyword, whitespace, the app id GitHub
# recorded for that context, whitespace, then the exact check name to the end of
# the line. A '#' starts a comment only at column 0, so a name may contain one.
# Whitespace around a name is stripped and is not part of it.
#
# Producer keywords. An unknown one is an error rather than an assumed external,
# so a typo cannot become a silently skipped check. The app id is measured, not
# chosen, and the gate refuses a record whose keyword and app id disagree:
#
#   workflow          15368  a job in .github/workflows/**; the name is checked
#   actions-external  15368  a GitHub Actions workflow with NO file in this
#                            repository, the CodeQL default setup
#   code-scanning     57789  the GitHub code scanning results check, one context
#                            per analysis tool
#
# Only `workflow` records can be held against the tree. The others are recorded
# so the count is complete and so nobody reads their absence from
# .github/workflows/** as drift. From the API, an `actions-external` record is
# indistinguishable from a renamed job, which is why a human classifies it once
# and the gate then keeps that classification honest in both directions.
#
# HOW TO REFRESH THIS FILE after a DELIBERATE change to branch protection:
#
#     make refresh-required-checks
#     # or: ./scripts/check-required-checks.sh --refresh
#
# It rewrites the file from the live API and refuses to guess: a context that is
# neither a job name in this tree nor already classified here stops the refresh
# and asks you to classify it by hand.
#
# Generated from: gh api repos/{repo}/branches/{branch}/protection
# records: {total} ({percounts})
"""

if MODE == "--refresh":
    live = []
    for line in os.environ["LIVE"].splitlines():
        if not line.strip():
            continue
        app, _, name = line.partition("\t")
        live.append((app.strip(), name.strip()))
    old = {}
    if os.path.exists(MANIFEST):
        for _, producer, _app, name, _ in parse_manifest(MANIFEST)[0]:
            if name:
                old[name] = producer
    out, unknown = [], []
    for app, name in live:
        if app == APP_ACTIONS and match(name):
            out.append(("workflow", app, name))
        elif name in old and old[name] in PRODUCERS and old[name] != "workflow":
            out.append((old[name], app, name))
        elif app == APP_GHAS:
            out.append(("code-scanning", app, name))
        else:
            unknown.append((app, name))
    if unknown:
        print("FAIL: --refresh will not guess a producer for these contexts.")
        for app, name in unknown:
            print(f"  app {app}  {name}")
        print()
        print("Each is required from GitHub Actions, no job in")
        print(".github/workflows/** answers to that name, and none is already")
        print(f"classified in {MANIFEST}.")
        print()
        print("Two very different things look like this. One: a workflow that")
        print("lives outside the repository, such as the CodeQL default setup.")
        print("Two: a job in this tree that was RENAMED while branch protection")
        print("kept asking for the old name. Only you can tell them apart. Add a")
        print("line for each with the producer that really makes it, then run")
        print("the gate to confirm.")
        sys.exit(3)
    per = {}
    for producer, _app, _name in out:
        per[producer] = per.get(producer, 0) + 1
    kw = max((len(p) for p, _, _ in out), default=8)
    aw = max((len(a) for _, a, _ in out), default=5)
    body = "".join(f"{p.ljust(kw)}  {a.ljust(aw)}  {n}\n" for p, a, n in out)
    percounts = ", ".join(f"{k} {per[k]}" for k in sorted(per))
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        fh.write(HEADER.format(branch=BRANCH, repo=REPO,
                               total=len(out), percounts=percounts))
        fh.write(body)
    print(f"wrote {MANIFEST}: {len(out)} record(s) ({percounts}).")
    sys.exit(0)

# ------------------------------------------------------------------ gate
if not os.path.exists(MANIFEST):
    print(f"FAIL: {MANIFEST} is missing. Run --refresh to create it.")
    sys.exit(1)

records, counts = parse_manifest(MANIFEST)
problems, seen, per = [], {}, {}

for lineno, producer, app, name, raw in records:
    if producer not in PRODUCERS:
        problems.append(
            f"{MANIFEST}:{lineno}: unknown producer {producer!r}; expected one "
            f"of {', '.join(sorted(PRODUCERS))}")
        continue
    if not name:
        problems.append(
            f"{MANIFEST}:{lineno}: record needs producer, app id and a check "
            f"name; got {raw!r}")
        continue
    if name in seen:
        problems.append(
            f"{MANIFEST}:{lineno}: duplicate check name {name!r} "
            f"(first at line {seen[name]})")
        continue
    seen[name] = lineno
    per[producer] = per.get(producer, 0) + 1

    want_app, must_resolve, prose = PRODUCERS[producer]
    if app != want_app:
        problems.append(
            f"{MANIFEST}:{lineno}: {name!r} is recorded as '{producer}', which "
            f"means app {want_app}, but the app id beside it is {app!r}. "
            f"Relabelling a record does not change who produces it.")
        continue

    hit = match(name)
    if must_resolve:
        if hit is None:
            problems.append(
                f"{MANIFEST}:{lineno}: required check {name!r} has NO job of "
                f"that name in .github/workflows/**. Either a job was renamed "
                f"and branch protection still asks for the old name, or the job "
                f"was deleted. Both make the requirement unsatisfiable, and the "
                f"pull request waits for a context that never arrives.")
        elif not any(e in PR_CAPABLE for e in hit[3]):
            problems.append(
                f"{MANIFEST}:{lineno}: required check {name!r} is declared in "
                f"{hit[1]}, which triggers on {hit[3]} and therefore cannot "
                f"report on a pull request head.")
    elif hit is not None:
        problems.append(
            f"{MANIFEST}:{lineno}: {name!r} is recorded as '{producer}' "
            f"({prose}), but {hit[1]} declares a job of exactly that name. One "
            f"of the two is wrong, and while it is wrong this gate skips a "
            f"check it could make.")

if counts is None:
    problems.append(
        f"{MANIFEST}: the header line '# records: N (keyword N, ...)' is "
        f"missing. It is what catches a truncated file.")
else:
    total, header_per = counts
    if total != len(records) or header_per != per:
        have = ", ".join(f"{k} {per[k]}" for k in sorted(per))
        want = ", ".join(f"{k} {header_per[k]}" for k in sorted(header_per))
        problems.append(
            f"{MANIFEST}: the header states {total} records ({want}), the file "
            f"holds {len(records)} ({have}). Run --refresh after a deliberate "
            f"change to branch protection.")

for e in PARSE_ERRORS:
    problems.append(f"workflow will not parse: {e}")

if problems:
    print(f"::error::required-check drift ({MANIFEST} vs .github/workflows/**)")
    for p in problems:
        print(f"  {p}")
    print()
    print("A required status check is bound to a job by its NAME and by nothing")
    print("else. When the two names differ the context never reports again and")
    print("the enforcement is gone without a sound. See .claude/rules/claims.md,")
    print("section 'The tools that answer a different question'.")
    sys.exit(1)

wf = per.get("workflow", 0)
jobs = len(set((r[1], r[2]) for r in ROWS))
print(f"OK: {len(records)} required context(s) in {MANIFEST}. {wf} are produced "
      f"by a job in this tree, and every one of them has a job of exactly that "
      f"name among the {len(ROWS)} check names this tree declares "
      f"({jobs} jobs, matrix names expanded).")
print(f"    {len(records) - wf} come from outside the tree and are recorded as "
      f"such, not checked:")
for _, producer, _app, name, _ in records:
    if producer != "workflow" and name:
        print(f"      {name}  ({PRODUCERS[producer][2]})")
print("    NOT checked here, and deliberately so:")
print("      a. whether these names still equal what branch protection requires")
print("         today. Only scripts/check-required-checks.sh --refresh reads the")
print("         live API, and running it is a human act.")
print("      b. whether a declared job is REACHED on a pull request; a path")
print("         filter, an `if:` or a skipped `needs:` leaves it unreported.")
print("      c. check runs made through `workflow_call`, which GitHub renames")
print("         to '<calling job> / <called job>'.")
PY
