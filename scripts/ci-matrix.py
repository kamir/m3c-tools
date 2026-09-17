#!/usr/bin/env python3
"""ci-matrix.py: one row per CI job, and a hygiene gate over those rows.

WHY THIS EXISTS

A workflow rebuild moves jobs between files, renames them, and changes what
triggers them. Every one of those is a change that can go unnoticed, because a
job which stops running leaves its name in the tree behind it, and a required
context bound to a name that no longer reports is green by absence.

scripts/check-required-checks.sh already holds the required NAMES against the
job names. It deliberately answers one question only. It does not answer "which
jobs exist, on which runner, with which timeout, reachable from which event",
and that is the question a before/after comparison of a rebuild asks. So this
prints exactly that, one row per EXPANDED job name, sorted, with no timestamp
and no absolute path in the output: two runs across a rebuild diff cleanly.

    ./scripts/ci-matrix.py              the table, tab separated
    ./scripts/ci-matrix.py --summary    the counts
    ./scripts/ci-matrix.py --json       the same rows, machine readable
    ./scripts/ci-matrix.py --check      the hygiene gate, exit 1 on a finding

HOW TO COMPARE ACROSS A REBUILD

No snapshot of the table is committed, on purpose: a checked-in "before" file
is correct on the day it is written and quietly wrong every day after. The
comparison is made against git instead, so the "before" side is always the tree
it claims to be:

    git worktree add /tmp/before origin/master
    ( cd /tmp/before && python3 - ) < scripts/ci-matrix.py > /tmp/before.tsv
    ./scripts/ci-matrix.py > /tmp/after.tsv
    diff /tmp/before.tsv /tmp/after.tsv

The script is fed on stdin so the CURRENT version of it reads the OLD tree: a
rebuild that also changes this script must not measure its two sides with two
different rulers.

WHAT A ROW SAYS

  file  job  name  runs_on  timeout  events  pr  required  concurrency  needs

  pr        the job's WORKFLOW can report on a pull request head at all.
            `pull_request`, `pull_request_target` and `workflow_call` can; a
            `push` can, EXCEPT when filtered to tags alone, because a pull
            request head is never a tag. Same rule as check-required-checks.sh.
  required  the expanded name is a `workflow` record in
            docs/security/required-checks.txt.

WHAT A ROW DOES NOT SAY

  It reads declarations, not runs. A job behind a path filter, an `if:` or a
  skipped `needs:` chain is declared and may still never report. `pr` is the
  weaker claim that the workflow can be triggered, and it is not a claim that
  this job runs.

WHAT --check ENFORCES, and why each one

  1. every job declares `timeout-minutes`. GitHub's default is 360 minutes, so
     an omitted key is a six-hour lease on a runner for a job that hangs. A job
     that CALLS a reusable workflow is exempt, because GitHub rejects
     `timeout-minutes` on such a job: the called workflow carries its own.

  2. every workflow that can report on a pull request declares a `concurrency`
     group. Without one, a second push to a branch leaves the first run going,
     and the two compete for the same runners.

  3. every `runs-on` that names a self-hosted runner is spelled EXACTLY as
     TRUSTED_LINUX below. A self-hosted runner is a persistent machine: code
     from an untrusted pull request executing on it can read the runner token
     and whatever else that machine holds. The one blessed spelling routes
     untrusted heads to a GitHub-hosted runner instead, and holding it verbatim
     is what keeps a later edit from quietly loosening it. Not "contains
     self-hosted, looks guarded": one string, compared whole.

     Untrusted means two things here, and the second is the one that is easy to
     miss. A head from a FORK is untrusted in the obvious way. A pull request
     from `dependabot[bot]` has its head branch inside this repository, so every
     fork test calls it trusted, and yet what it changes is precisely the set of
     third-party code that `go test` will then execute, and this repository arms
     auto-merge on those pull requests (owner decision E2). Both route away.

     The leading `vars.CI_SELF_HOSTED != 'on'` is the kill switch, and its
     default direction is the point. The repository has ONE self-hosted runner,
     and three of the jobs routed to it are required contexts on master: if that
     machine is off, those checks never report and nothing can merge. Unsetting
     the variable, or setting it to anything but `on`, sends every routed job
     back to a GitHub-hosted runner within one API call and with no commit. It
     is opt-IN, so a lost or forgotten variable degrades to slower and costlier
     rather than to stuck.

  4. no job name is declared twice within one workflow file under two job ids.
     Two jobs reporting the same context in one run make the required check a
     race between them.

The YAML loader REFUSES duplicate keys. GitHub does too. A loader that tolerates
them answers "can I parse this somehow" instead of "is this the document Actions
will run", which is the error that cost this repository fourteen runs on
2026-09-06; .github/workflows/pin-guard.yml carries that account in full.
"""

import json
import os
import re
import sys

import yaml

# The ONE spelling a self-hosted `runs-on` may carry. Compared whole, never by
# substring: a rule matched loosely is a rule that drifts.
TRUSTED_LINUX = (
    "${{ (vars.CI_SELF_HOSTED != 'on' || (github.event_name == 'pull_request' && "
    "(github.event.pull_request.head.repo.full_name != github.repository || "
    "github.event.pull_request.user.login == 'dependabot[bot]'))) "
    "&& fromJSON('[\"ubuntu-latest\"]') "
    "|| fromJSON('[\"self-hosted\",\"Linux\",\"X64\",\"master2\"]') }}"
)

EXPR = re.compile(r"\$\{\{([^}]*)\}\}")


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys, as GitHub does."""


def _no_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                "duplicate key %r" % (key,), key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


def on_key(doc):
    """`on:` parses as the YAML 1.1 boolean True. Accept both spellings."""
    for k in (True, "on"):
        if k in doc:
            return doc[k]
    return None


def events(doc):
    raw = on_key(doc)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return list(raw)
    return list(raw.keys())


def can_report_on_pr(doc):
    raw = on_key(doc)
    if raw is None:
        return False
    if isinstance(raw, str):
        raw = {raw: None}
    if isinstance(raw, list):
        raw = dict.fromkeys(raw)
    for ev, cfg in raw.items():
        if ev in ("pull_request", "pull_request_target", "workflow_call"):
            return True
        if ev == "push":
            # A push filtered to tags alone never reports on a pull request head.
            if isinstance(cfg, dict) and "tags" in cfg and "branches" not in cfg:
                return False
            return True
    return False


def literal_axes(matrix):
    """The matrix axes whose values are literals in the YAML, in order."""
    axes = {}
    for key, val in (matrix or {}).items():
        if key in ("include", "exclude"):
            continue
        if isinstance(val, list) and all(
                isinstance(x, (str, int, float, bool)) for x in val):
            axes[key] = [str(x) for x in val]
    return axes


def expand(name, matrix):
    """Expand ${{ matrix.x }} against literal values. A survivor stays a pattern."""
    if not name or not EXPR.search(name):
        return [name]
    axes = literal_axes(matrix)
    if not axes:
        return [name]
    out = [name]
    for axis, values in axes.items():
        pat = re.compile(r"\$\{\{\s*matrix\." + re.escape(axis) + r"\s*\}\}")
        nxt = []
        for cand in out:
            if pat.search(cand):
                nxt.extend(pat.sub(v, cand) for v in values)
            else:
                nxt.append(cand)
        out = nxt
    return out


def default_matrix_names(job_id, matrix):
    """A matrix job with no `name:` reports GitHub's default `<id> (v1, v2)`."""
    axes = list(literal_axes(matrix).values())
    if not axes:
        return [job_id]
    combos = [[]]
    for values in axes:
        combos = [c + [v] for c in combos for v in values]
    return ["%s (%s)" % (job_id, ", ".join(c)) for c in combos]


def runner_of(job):
    raw = job.get("runs-on")
    if raw is None:
        return "reusable" if "uses" in job else "n/a"
    if isinstance(raw, list):
        return ",".join(str(x) for x in raw)
    return str(raw)


def required_names(root):
    path = os.path.join(root, "docs", "security", "required-checks.txt")
    names = set()
    if not os.path.exists(path):
        return names
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split(None, 2)
            if len(parts) == 3 and parts[0] == "workflow":
                names.add(parts[2].strip())
    return names


def rows(root):
    wfdir = os.path.join(root, ".github", "workflows")
    req = required_names(root)
    out = []
    for filename in sorted(os.listdir(wfdir)):
        if not filename.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(wfdir, filename), encoding="utf-8") as handle:
            doc = yaml.load(handle, Loader=StrictLoader)
        evs = ",".join(sorted(events(doc))) or "none"
        pr = "yes" if can_report_on_pr(doc) else "no"
        has_wf_concurrency = "concurrency" in doc
        for job_id, job in (doc.get("jobs") or {}).items():
            strategy = job.get("strategy")
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            if job.get("name"):
                names = expand(str(job["name"]), matrix)
            elif matrix:
                names = default_matrix_names(job_id, matrix)
            else:
                names = [job_id]
            timeout = job.get("timeout-minutes")
            needs = job.get("needs")
            if isinstance(needs, list):
                needs = ",".join(needs)
            for name in names:
                out.append({
                    "file": filename,
                    "job": job_id,
                    "name": name,
                    "runs_on": runner_of(job),
                    "timeout": str(timeout) if timeout is not None else "none",
                    "events": evs,
                    "pr": pr,
                    "required": "yes" if name in req else "no",
                    "concurrency": ("workflow" if has_wf_concurrency
                                    else ("job" if job.get("concurrency") else "none")),
                    "needs": needs or "",
                    "reusable": "yes" if "uses" in job else "no",
                })
    out.sort(key=lambda r: (r["file"], r["job"], r["name"]))
    return out


def check(data):
    """The hygiene gate. Returns a list of findings; empty means pass."""
    findings = []

    seen_jobs = set()
    for row in data:
        if row["reusable"] == "yes":
            continue  # GitHub rejects timeout-minutes on a reusable-workflow call.
        # One finding per JOB, not per expanded matrix name: `timeout-minutes`
        # is a job-level key, so a matrix job would otherwise be reported once
        # per axis value and the count would describe names, not jobs.
        ident = (row["file"], row["job"])
        if ident in seen_jobs:
            continue
        seen_jobs.add(ident)
        if row["timeout"] == "none":
            findings.append(
                "%s: job '%s' declares no timeout-minutes; the default is 360"
                % (row["file"], row["job"]))

    seen_pr_files = set()
    for row in data:
        if row["pr"] == "yes" and row["concurrency"] == "none":
            if row["file"] not in seen_pr_files:
                seen_pr_files.add(row["file"])
                findings.append(
                    "%s: reaches a pull request and declares no concurrency group"
                    % row["file"])

    for row in data:
        if "self-hosted" not in row["runs_on"]:
            continue
        if row["runs_on"] != TRUSTED_LINUX:
            findings.append(
                "%s: job '%s' runs-on names a self-hosted runner but is not the "
                "blessed trusted-routing spelling (see TRUSTED_LINUX in this "
                "script); untrusted heads could execute on a persistent machine"
                % (row["file"], row["job"]))

    per_file = {}
    for row in data:
        per_file.setdefault((row["file"], row["name"]), set()).add(row["job"])
    for (filename, name), job_ids in sorted(per_file.items()):
        if len(job_ids) > 1:
            findings.append(
                "%s: name '%s' is declared by %d jobs (%s); one context, two "
                "producers" % (filename, name, len(job_ids), ", ".join(sorted(job_ids))))

    return findings


def main():
    root = os.environ.get("CI_MATRIX_ROOT") or os.getcwd()
    args = sys.argv[1:]
    data = rows(root)

    if "--json" in args:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    if "--summary" in args:
        print("jobs (expanded names)       %d" % len(data))
        print("required (workflow records) %d"
              % sum(1 for r in data if r["required"] == "yes"))
        no_timeout = {(r["file"], r["job"]) for r in data
                      if r["timeout"] == "none" and r["reusable"] == "no"}
        print("without timeout-minutes     %d" % len(no_timeout))
        print("without concurrency group   %d"
              % sum(1 for r in data if r["concurrency"] == "none"))
        print("self-hosted runners         %d"
              % sum(1 for r in data if "self-hosted" in r["runs_on"]))
        print("macos runners               %d"
              % sum(1 for r in data if "macos" in r["runs_on"]))
        print("windows runners             %d"
              % sum(1 for r in data if "windows" in r["runs_on"]))
        return 0

    if "--check" in args:
        findings = check(data)
        if findings:
            for f in findings:
                print("::error::%s" % f)
            print("")
            print("%d finding(s). The rules and the reason for each are in the "
                  "header of scripts/ci-matrix.py." % len(findings))
            return 1
        print("OK: %d jobs; every job has a timeout, every pull-request workflow "
              "has a concurrency group, every self-hosted runs-on carries the "
              "trusted-routing guard, no name has two producers." % len(data))
        return 0

    header = ("file", "job", "name", "runs_on", "timeout", "events", "pr",
              "required", "concurrency", "needs")
    print("\t".join(header))
    for row in data:
        print("\t".join(row[h] for h in header))
    return 0


if __name__ == "__main__":
    sys.exit(main())
