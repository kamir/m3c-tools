#!/usr/bin/env python3
"""sarif-for-code-scanning.py: make a gosec SARIF file ingestible, or say why not.

WHAT WENT WRONG, measured before this script existed.

Code Scanning recorded 344 gosec analyses between 2026-09-03 and 2026-09-15.
343 of them carry `results_count: 0`. The runs arrived, were accepted as runs,
and every finding in them was discarded, while the Actions job "gosec SAST
(SARIF -> Code Scanning)" reported success every single time.

That is worse than not ingesting at all. A tool that is absent from the
dashboard is visibly absent. A tool that is present with zero findings reads as
a clean bill of health, and gosec has 502 findings on this tree.

THREE LAYERS OF SILENCE, which is why it stood for twelve days.

    continue-on-error: true    the upload could not fail the Actions job
    results_count: 0           the dashboard showed a clean tool, not a broken one
    conclusion: neutral        and neutral does not block a merge

The rejection surfaced only as a separate check run named `gosec`, posted by
the github-advanced-security app, titled "Error when processing the SARIF
file". That check IS a required context on master, which invites the guess
that it blocked merges and forced the issue. It did not, measured twice: PR
#294 merged with that exact neutral conclusion, and PR #265 reported
mergeStateStatus CLEAN while carrying it. Nothing anywhere pushed back. It was
found by reading a check-run title while diagnosing something else.

A trap worth recording, because it cost an hour and produced a confidently
wrong first diagnosis: `?tool_name=gosec` returns an empty list. The SARIF
names the tool "Golang security checks by gosec", and the filter matches that
string exactly. An empty answer there means "no tool by that name", not "no
analyses", and the two look identical from the outside.

THE CAUSE, measured on the tree at 19be7dc with gosec v2.29.0 and the exact
relativize step the workflow used:

    findings total                  525
      artifactLocation missing       23   all G115, all in cgo-generated code
      uri pointing nowhere            0
      uri pointing at a real file   502

The 23 carry snippets like `_Cfunc_CString /*line :801:19*/`, which is cgo's
generated Go, written to a temporary build directory. There IS no repository
file to name, so gosec emits `"artifactLocation": {}`, and Code Scanning
rejects the whole document over it. One unnameable location voided 502 good
findings.

WHAT THIS SCRIPT DOES ABOUT IT.

It relativizes the paths (unchanged from the old sed step), then DROPS the
locations that name no file, and reports how many and under which rule. It is
deliberately not silent: a dropped finding is a finding nobody will see, and
the count belongs in the job log where the next person can read it.

Then it VERIFIES what it produced. If a location survives that is still
missing or still absolute, the script exits 1 and names it, rather than
handing Code Scanning a document it will reject again. Checking its own output
is the whole point: the step it replaces believed its sed had worked.

Usage:
    scripts/sarif-for-code-scanning.py <in.sarif> <out.sarif> [--workspace DIR]

--workspace defaults to $GITHUB_WORKSPACE, else the current directory.
"""

import argparse
import collections
import json
import os
import sys


def relativize(uri, workspace):
    """Strip the file:// scheme and the workspace prefix. Repo-relative or bust."""
    if not uri:
        return None
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    if workspace and uri.startswith(workspace + os.sep):
        uri = uri[len(workspace) + 1:]
    return uri or None


def clean_locations(locations, workspace, unnameable, unrelativized):
    """Split locations into three: repo-relative (kept), nameless, still absolute.

    The two rejects are NOT the same case and must not share a fate.

    A location with no uri at all names no file in the repository, so Code
    Scanning could not display it even if it accepted the document. Dropping it
    is the only thing left, and the caller reports the count.

    A location that is still ABSOLUTE after relativizing is a different animal:
    it names a real file, and the only reason it did not become repo-relative
    is that the workspace prefix did not match. Dropping that one would hide a
    broken relativization behind a shrinking finding count, which is precisely
    the failure mode this script exists to end. It is collected and made fatal.
    """
    kept = []
    for loc in locations:
        art = loc.get("physicalLocation", {}).get("artifactLocation", {})
        uri = relativize(art.get("uri"), workspace)
        if uri is None:
            unnameable.append(loc)
        elif uri.startswith("/"):
            unrelativized.append(uri)
        else:
            art["uri"] = uri
            kept.append(loc)
    return kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("outfile")
    ap.add_argument("--workspace", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    args = ap.parse_args()

    workspace = os.path.abspath(args.workspace).rstrip(os.sep)
    with open(args.infile, encoding="utf-8") as fh:
        doc = json.load(fh)

    total = 0
    kept_results = 0
    unnameable = []
    unrelativized = []
    dropped_rules = collections.Counter()

    for run in doc.get("runs", []):
        results = []
        for result in run.get("results", []):
            total += 1
            result["locations"] = clean_locations(
                result.get("locations", []), workspace, unnameable, unrelativized)
            if "relatedLocations" in result:
                result["relatedLocations"] = clean_locations(
                    result["relatedLocations"], workspace, unnameable, unrelativized)
            if not result["locations"]:
                dropped_rules[result.get("ruleId") or "?"] += 1
                continue
            results.append(result)
            kept_results += 1
        run["results"] = results

    if unrelativized:
        print(f"FAIL: {len(unrelativized)} Ortsangabe(n) sind nach dem Relativieren",
              file=sys.stderr)
        print(f"      immer noch absolut. Der Arbeitsbaum war {workspace!r};", file=sys.stderr)
        print("      stimmt --workspace nicht, wird hier still nichts gekuerzt.", file=sys.stderr)
        for uri in sorted(set(unrelativized))[:10]:
            print(f"  {uri}", file=sys.stderr)
        return 1

    print(f"sarif-for-code-scanning: {total} Fundstellen gelesen, {kept_results} behalten")
    if dropped_rules:
        gone = total - kept_results
        print(f"  {gone} verworfen ({len(unnameable)} Ortsangabe(n)), weil keine")
        print("  ihrer Ortsangaben eine Datei im Baum benennt")
        print("  (cgo erzeugt seinen Go-Code in einem Bauverzeichnis; die Datei")
        print("   existiert im Repository nicht, also kann Code Scanning sie nicht zeigen)")
        for rule, n in sorted(dropped_rules.items()):
            if n:
                print(f"    {rule}: {n}")

    # Pruefe das eigene Ergebnis. Der Schritt, den dieses Skript ersetzt, hat
    # seinem eigenen sed geglaubt; daran ist die Aufnahme jahrelang gescheitert.
    bad = []
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []) + result.get("relatedLocations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                if not uri or uri.startswith("/") or uri.startswith("file:"):
                    bad.append((result.get("ruleId"), uri))
    if bad:
        print(f"FAIL: {len(bad)} Fundstelle(n) sind weiter nicht repo-relativ:", file=sys.stderr)
        for rule, uri in bad[:10]:
            print(f"  {rule}: {uri!r}", file=sys.stderr)
        return 1

    with open(args.outfile, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    print(f"sarif-for-code-scanning: PASS, {kept_results} Fundstellen sind repo-relativ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
