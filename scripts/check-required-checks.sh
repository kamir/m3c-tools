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
# made mechanical for one instance of it, the workflow job names. The reference
# names the file and not a section inside it, because a section title is itself
# a binding through a string and would be the same mistake one level down.
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
#   1. every `workflow` record resolves to a job name declared LITERALLY in the
#      workflow files, matrix names expanded. A job name that still holds an
#      unresolved `${{ }}` expression can never satisfy a required record: see
#      MATRIX JOBS below for why that is fail-closed and not pedantry.
#   2. at least one of the workflows declaring such a job can report on a pull
#      request head at all. `pull_request`, `pull_request_target` and
#      `workflow_call` always can; a `push` can, EXCEPT when it is filtered to
#      tags alone, because a pull request head is never a tag.
#   3. no record classified as produced OUTSIDE the tree is in fact produced by
#      a job inside it, which would mean the classification is wrong and the
#      gate is skipping a check it could have made.
#   4. the producer keyword agrees with the app id recorded beside it, and every
#      `actions-external` record names one of the contexts allow-listed in this
#      script. What the app id can and cannot do is set out under HOW THE THREE
#      PRODUCERS ARE TOLD APART; the allow-list is what actually stops a record
#      being relabelled around check 1.
#   5. the manifest is internally consistent: known keywords, no duplicate
#      names, at least MIN_RECORDS records, and header counts equal to what was
#      parsed.
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
#   d. whether every gate in this tree that OUGHT to be required actually is.
#      This runs one way only: it asks whether every required name is
#      satisfiable, never whether every gate is required. A new blocking job
#      that nobody added to branch protection passes here in silence. That is
#      not an oversight to be fixed with a warning: 42 of the 65 names this tree
#      declares are deliberately not required, so the question is not
#      mechanically decidable and belongs to a human.
#
# HOW THE THREE PRODUCERS ARE TOLD APART
#
# `gh api .../protection` returns an app id beside every required context, and
# it separates the code-scanning class without guesswork. Measured on
# 2026-09-10:
#
#     app 15368  github-actions             27 of the 29 contexts
#     app 57789  github-advanced-security     2, "CodeQL" and "gosec"
#
# The app id does exactly that much and no more. It tells `code-scanning` apart
# from the other two; it does NOT tell `workflow` apart from `actions-external`,
# because both of those are app 15368. Relabelling a record from `workflow` to
# `actions-external` would therefore switch check 1 off for that context while
# every app id still agreed, and a job renamed in the same commit would sail
# through: precisely the failure of 2026-09-10, wearing the gate's own uniform.
# ACTIONS_EXTERNAL_ALLOWED below is what closes that, by naming the four
# contexts that may carry the keyword. Adding a fifth means editing this script,
# which is a visible act in a reviewed diff, and that is the whole point.
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
# template is kept as a PATTERN, shown by `--list`, and it can never satisfy a
# required record.
#
# That last clause is the load-bearing one. A pattern is matched by turning each
# surviving `${{ ... }}` into `.*`, so a name that is nothing but an expression
# collapses to `^.*$` and would answer to every required context at once. Read
# as caution it sounds careful; measured, it is a blanket permission, and one
# workflow file declaring one such job would have emptied check 1 for all 23
# records. So a pattern is evidence for a human reading `--list` and never
# evidence for the gate: a required context whose only candidate is a pattern is
# reported as drift, with the remedy being to give that job a literal name.
#
# Today this machinery is exercised and inconsequential at once: all three
# matrices in the tree expand to literals, zero rows stay patterns, and no
# required context hangs off a matrix at all. The two required names that LOOK
# matrix-shaped, "Binary Smoke Test (windows-latest)" and "Trust Surface
# (windows-latest)", are typed out by hand in windows-gate.yml.
#
# The include/exclude merge implemented here is GitHub's rule in its ordinary
# form: the cartesian product of the plain keys, minus `exclude`, then each
# `include` entry merged into every combination it is compatible with, or
# appended when it is compatible with none. Exotic overrides are not modelled.
#
# WHICH FILES ARE READ
#
# `.github/workflows/*.yml` and `.github/workflows/*.yaml`, because GitHub
# accepts both extensions. The tree holds 17 files and all of them are `.yml`,
# so reading the second extension changes nothing today; it is here so that a
# `.yaml` file cannot become a place where check 3 stops looking.
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
#       3 the gate could not run at all, or --refresh could not complete (no
#         python3, no PyYAML, no gh, no permission, a name it will not classify
#         on its own). Exit 3 is a statement about the TOOLING and exit 1 a
#         statement about the TREE, and keeping them apart is why a missing
#         PyYAML is not allowed to look like drift.
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

# The tooling before the tree. Without this, a missing PyYAML ends in a raw
# traceback and exit 1, which is the code reserved for drift: "the gate could
# not run" and "the gate found drift" would be the same signal.
if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: this gate needs python3, and it is not on PATH." >&2
  exit 3
fi
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "FAIL: this gate needs python3 with PyYAML; 'import yaml' failed." >&2
  echo "      That is a statement about the tooling and not about the tree," >&2
  echo "      so this is exit 3 and not exit 1." >&2
  exit 3
fi

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
import collections, glob, itertools, os, re, sys, yaml

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
        "a job in the workflow files"),
    "actions-external": (
        APP_ACTIONS, False,
        "a GitHub Actions workflow with no file in this repository, "
        "the CodeQL default setup"),
    "code-scanning": (
        APP_GHAS, False,
        "the GitHub code scanning results check, one context per analysis tool"),
}

# The closed list of contexts that may carry `actions-external`. It exists
# because `workflow` and `actions-external` share app id 15368, so the app id
# cannot tell them apart, and without this a record could be relabelled from
# `workflow` to `actions-external` to switch its name check off. These four are
# the CodeQL default setup's analyses, measured on 2026-09-10. A fifth external
# context means editing this line, in a diff a reviewer sees.
ACTIONS_EXTERNAL_ALLOWED = {
    "Analyze (go)",
    "Analyze (actions)",
    "Analyze (python)",
    "Analyze (javascript-typescript)",
}

# A floor that does not come from the file being checked. The header count
# catches a TRUNCATED manifest, but it cannot catch a manifest emptied on
# purpose with the header pulled down to match: that is internally consistent
# and would print "OK: 0 required context(s)". Branch protection required 29
# contexts on 2026-09-10; the floor sits below that so ordinary churn does not
# trip it, and far enough above zero that gutting the file is a red build and a
# deliberate edit here.
MIN_RECORDS = 25

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


def on_block(doc):
    # A bare `on:` is parsed as the boolean True by YAML 1.1.
    on = doc.get("on", doc.get(True))
    if isinstance(on, dict):
        return on
    if isinstance(on, list):
        return {str(e): None for e in on}
    if isinstance(on, str):
        return {on: None}
    return {}


def pr_capable(on):
    """Can a workflow with this `on:` block report on a PULL REQUEST head?

    `pull_request`, `pull_request_target` and `workflow_call` always can. A
    `push` normally can too, because pushing the branch behind a pull request
    produces check runs on that same head commit. A push filtered to TAGS and
    nothing else cannot, since a pull request head is never a tag.

    That last case is not hypothetical. release.yml is `on: {push: {tags: v*}}`
    and declares jobs named "CLI/manual consistency (docaudit)" and "Build macOS
    (arm64 + amd64)", the same names ci.yml declares. Reading only the `push`
    key, a rename of the ci.yml copy left this gate green, because the tag-only
    copy went on carrying the name while the copy that actually reports on pull
    requests had been renamed away.
    """
    for ev in ("pull_request", "pull_request_target", "workflow_call"):
        if ev in on:
            return True
    if "push" in on:
        spec = on["push"]
        if isinstance(spec, dict):
            # `tags:` is an allow-list, so a push filtered by it and nothing
            # else runs for tag pushes only. `tags-ignore:` is the opposite, an
            # exclusion, and a push carrying only that still runs for every
            # branch: treating it as tag-only would be a FALSE red, which in a
            # gate meant to be believed costs as much as a false green.
            if "tags" in spec and not any(
                    k in spec for k in ("branches", "branches-ignore")):
                return False
        return True
    return False


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


def workflow_files():
    """Both extensions GitHub accepts, so a .yaml file is not a blind spot."""
    return sorted(glob.glob(".github/workflows/*.yml")
                  + glob.glob(".github/workflows/*.yaml"))


def resolve():
    """Every check-run name declared: (name, file, job, events, kind, prcap)."""
    rows, parse_errors = [], []
    for f in workflow_files():
        try:
            with open(f, encoding="utf-8") as fh:
                doc = yaml.load(fh, Strict) or {}
        except Exception as e:                       # noqa: BLE001
            parse_errors.append(f"{f}: {e}")
            continue
        on = on_block(doc)
        events, prcap = list(on), pr_capable(on)
        for jid, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            matrix = (job.get("strategy") or {}).get("matrix")
            combos = combinations(matrix) if matrix else []
            explicit = job.get("name")
            if not combos:
                nm = str(explicit) if explicit else jid
                rows.append((nm, f, jid, events,
                             "pattern" if EXPR.search(nm) else "literal", prcap))
                continue
            for c in combos:
                nm = (substitute(str(explicit), c) if explicit
                      else f"{jid} ({', '.join(str(v) for v in c.values())})")
                rows.append((nm, f, jid, events,
                             "pattern" if EXPR.search(nm) else "literal", prcap))
    return rows, parse_errors


ROWS, PARSE_ERRORS = resolve()

# EVERY declaration of a name is kept, not the last one parsed. Two files
# declaring the same job name is normal here (ci.yml and release.yml share
# two), and a dict would have hidden all but one of them, which is exactly how
# a tag-only copy came to answer for a renamed pull-request copy.
LITERALS = collections.defaultdict(list)
for _r in ROWS:
    if _r[4] == "literal":
        LITERALS[_r[0]].append(_r)
PATTERNS = [r for r in ROWS if r[4] == "pattern"]


def literal_hits(name):
    """Every job declaring exactly this name. The only evidence the gate takes."""
    return LITERALS.get(name, [])


def pattern_hits(name):
    """Jobs whose unresolved name COULD expand to this. Evidence for a human."""
    out = []
    for r in PATTERNS:
        rx = "^" + "".join(
            ".*" if p.startswith("${{") else re.escape(p)
            for p in re.split(r"(\$\{\{.*?\}\})", r[0]) if p) + "$"
        if re.match(rx, name):
            out.append(r)
    return out


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
    for name, f, jid, events, kind, prcap in sorted(ROWS):
        print(f"  {kind:8} {name}")
        print(f"           {f}  job:{jid}  on:{','.join(events)}"
              f"  pr-head:{'yes' if prcap else 'no'}")
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
# so a typo cannot become a silently skipped check:
#
#   workflow          15368  a job in the workflow files; the name is checked
#   actions-external  15368  a GitHub Actions workflow with NO file in this
#                            repository, the CodeQL default setup
#   code-scanning     57789  the GitHub code scanning results check, one context
#                            per analysis tool
#
# The app id is measured rather than chosen, and the gate refuses a record whose
# keyword and app id disagree. Note what that does and does not buy: it tells
# `code-scanning` apart from the other two, and it does NOT tell `workflow`
# apart from `actions-external`, because those two share app 15368. Relabelling
# a record between them is therefore blocked by a second, independent fetter:
# only the four CodeQL default-setup contexts allow-listed in
# scripts/check-required-checks.sh may carry `actions-external`, and any other
# name with that keyword is a hard error.
#
# Only `workflow` records can be held against the tree. The others are recorded
# so the count is complete and so nobody reads their absence from the workflow
# files as drift. From the API, an `actions-external` record is
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
        keep = old.get(name)
        if keep == "actions-external" and name not in ACTIONS_EXTERNAL_ALLOWED:
            keep = None          # never carry an unvetted relabel forward
        if app == APP_ACTIONS and literal_hits(name):
            out.append(("workflow", app, name))
        elif keep in PRODUCERS and keep != "workflow":
            out.append((keep, app, name))
        elif app == APP_GHAS:
            out.append(("code-scanning", app, name))
        else:
            unknown.append((app, name))
    if unknown:
        print("FAIL: --refresh will not guess a producer for these contexts.")
        for app, name in unknown:
            print(f"  app {app}  {name}")
        print()
        print("Each is required from GitHub Actions, no job in the workflow")
        print("files answers to that name, and none is already classified in")
        print(f"{MANIFEST} in a way this script will carry forward.")
        print()
        print("Two very different things look like this. One: a workflow that")
        print("lives outside the repository, such as the CodeQL default setup.")
        print("Two: a job in this tree that was RENAMED while branch protection")
        print("kept asking for the old name. Only you can tell them apart. An")
        print("external context must ALSO be added to ACTIONS_EXTERNAL_ALLOWED")
        print("in scripts/check-required-checks.sh, deliberately and in review.")
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

if not records:
    problems.append(
        f"{MANIFEST}: holds no records at all. An empty list of things to "
        f"check is not a clean result, it is a gate with nothing to say.")
elif len(records) < MIN_RECORDS:
    problems.append(
        f"{MANIFEST}: holds {len(records)} records, and this gate expects at "
        f"least {MIN_RECORDS}. Branch protection required 29 contexts when the "
        f"floor was set. Either protection was loosened on purpose, in which "
        f"case lower MIN_RECORDS in scripts/check-required-checks.sh in the "
        f"same commit, or the manifest was gutted and the header pulled down "
        f"to match.")

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

    if producer == "actions-external" and name not in ACTIONS_EXTERNAL_ALLOWED:
        problems.append(
            f"{MANIFEST}:{lineno}: {name!r} is recorded as 'actions-external', "
            f"which switches OFF the check that a job of that name exists, but "
            f"it is not one of the contexts allow-listed in "
            f"scripts/check-required-checks.sh. 'workflow' and "
            f"'actions-external' share app {APP_ACTIONS}, so the app id cannot "
            f"tell them apart and this list is what stops a record being "
            f"relabelled around the name check. If this context really is "
            f"produced outside the repository, add it to "
            f"ACTIONS_EXTERNAL_ALLOWED deliberately.")
        continue

    hits = literal_hits(name)
    if must_resolve:
        if not hits:
            pats = pattern_hits(name)
            if pats:
                where = ", ".join(sorted({p[1] for p in pats}))
                problems.append(
                    f"{MANIFEST}:{lineno}: required check {name!r} has no job "
                    f"of that name. It is matched only by a job whose `name:` "
                    f"still holds an unresolved expression ({where}), and a "
                    f"template is not a name: an expression is matched as '.*' "
                    f"here, so accepting it would let one such job answer for "
                    f"any required context at all. Give that job a literal "
                    f"name, or correct this record.")
            else:
                problems.append(
                    f"{MANIFEST}:{lineno}: required check {name!r} has NO job "
                    f"of that name in the workflow files. Either a job was "
                    f"renamed and branch protection still asks for the old "
                    f"name, or the job was deleted. Both make the requirement "
                    f"unsatisfiable, and the pull request waits for a context "
                    f"that never arrives.")
        elif not any(h[5] for h in hits):
            where = "; ".join(f"{h[1]} on:{','.join(h[3])}" for h in hits)
            # Name the reason that actually applies. A message that explains
            # the wrong cause sends the next reader to the wrong file, which is
            # the failure mode this whole gate is about, one level down.
            why = ("A push filtered to tags alone never produces a check run "
                   "on a pull request head."
                   if any("push" in h[3] for h in hits) else
                   "None of those events fires on a pull request head.")
            problems.append(
                f"{MANIFEST}:{lineno}: required check {name!r} is declared "
                f"{len(hits)} time(s), and no declaration can report on a pull "
                f"request head: {where}. {why}")
    elif hits:
        where = ", ".join(sorted({h[1] for h in hits}))
        problems.append(
            f"{MANIFEST}:{lineno}: {name!r} is recorded as '{producer}' "
            f"({prose}), but {where} declares a job of exactly that name. One "
            f"of the two is wrong, and while it is wrong this gate skips a "
            f"check it could make.")

if counts is None:
    problems.append(
        f"{MANIFEST}: the header line '# records: N (keyword N, ...)' is "
        f"missing. It is what catches a truncated file.")
elif not problems:
    # Only when no record is broken. A record skipped for a bad keyword or a
    # missing name is not counted in `per` but is counted in `records`, so
    # running this anyway would add a header-count complaint on top of the real
    # one and send the next reader to --refresh instead of to the broken line.
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
    print(f"::error::required-check drift ({MANIFEST} vs the workflow files)")
    for p in problems:
        print(f"  {p}")
    print()
    print("A required status check is bound to a job by its NAME and by nothing")
    print("else. When the two names differ the context never reports again and")
    print("the enforcement is gone without a sound. See .claude/rules/claims.md.")
    sys.exit(1)

wf = per.get("workflow", 0)
jobs = len(set((r[1], r[2]) for r in ROWS))
files = len(workflow_files())
print(f"OK: {len(records)} context(s) recorded as required in {MANIFEST}. This "
      f"is a statement about that file, not about branch protection; see limit "
      f"(a) below.")
print(f"    {wf} of them name a job in this tree. Each has a job of exactly "
      f"that name, declared in a workflow that can report on a pull request "
      f"head, among the {len(ROWS)} check names this tree declares "
      f"({jobs} jobs in {files} files, matrix names expanded).")
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
print("      d. whether every gate that OUGHT to be required actually is. This")
print("         gate runs one way only. Of the "
      f"{len(ROWS)} names this tree declares, {len(ROWS) - wf} are")
print("         deliberately not required, so a new blocking job that nobody")
print("         added to branch protection passes here in silence.")
PY
