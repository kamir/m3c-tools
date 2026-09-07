# Claims: what may be written as measured

Read this **before** writing, not after. It is the sibling of
[`prose-style.md`](prose-style.md), and unlike that one it has no hook behind
it. It is enforced by review, and by the fact that a wrong claim in this tree
is normally cheap to catch and expensive to have shipped.

## Where this comes from

The audit AUDIT-0001 ran nine changes past an adversarial reader. Seven came
back with findings, and after sorting them, one failure class accounted for
most of the volume:

> **A sentence printed beside measurements is read as a measurement.**

It appeared in a waiver register, in a calibration report, in a document
header, in a commit message, in a job name and in a tool's own help text. In
none of those places did anyone intend to mislead. The sentence was simply
written at a moment when the thing it described had not been run.

## The four rules

**1. A new sentence is a new claim.**
Measuring a defect and then describing the fix means the fix is undescribed.
Every line of documentation, comment or commit text that says something about
behaviour gets executed or read before it is written. The word "measured" is
reserved for what was measured.

**2. A promise in a header covers every line under it.**
"Every line checked against the binary" is either true or it gets narrowed.
The same holds for a tool that calls itself a gate, a job named "blocking",
and a script whose help text describes a reach wider than its code.

**3. Turning a behaviour off means hunting for whoever still claims it.**
After any behaviour change, search the documentation, the scripts, the
runbooks and the binary's own usage output for the old behaviour. The
acceptance helper counts: a helper that prints PASS on a file that no longer
does anything is worse than no helper.

**4. A search that finds nothing proves nothing until it has found something.**
Before writing "no occurrence remains", plant a known occurrence and show the
search finds it. Otherwise an empty result only establishes that the search
finds nothing.

## Four traps that cost time in this tree

- **Measure the object you are talking about.** Running a script without
  `--skillctl` measures whatever is on `$PATH`. Running a gate after a failed
  `cd` measures the wrong branch. Print the working directory or the binary
  path beside the result, in the same output.
- **Quote a number from the run it came from.** A line count taken before the
  last edit and a gate count taken after it do not belong in one report.
- **A push that says "everything up-to-date" is not a push.** A commit that
  failed at the pre-commit hook leaves the branch where it was.
  `git rev-list --count origin/master..HEAD` is the proof; the push output is
  not.
- **Numbers describe a population.** "28 of 48 jobs are required" says
  something; "28 required" says nothing. Name the population in the same line.

## Prefer the evidence that needs no counter-check

Two ways to show that a gate had drifted while the document it guards stayed
correct. One: quote the document, then quote the gate, and let the reader hold
both. Two: `git show <fix> --name-only`, one file, and it is the gate. The
second needs no second reading, because if the repair required no
documentation change, the question of who was stale is no longer open to
interpretation.

When a claim can be pinned by a single command whose output admits one
reading, look for that command before writing the paragraph. It is shorter,
and it survives being quoted out of context.

## Working next to other sessions

The repository working copy and the scratchpad directory are shared with
concurrent sessions and with the user.

- Work in your own `git worktree`, not in the shared checkout.
- Name every path you create after your own task. A directory called `before/`
  or `tmp/` in a shared scratchpad belongs to somebody.
- `rm -rf` only on a path you created in this session. Removing a directory
  because its name looks generic has already happened once.

## Verifying

There is no script for this file. The check is a question, asked before the
sentence is written:

> Did I run this, or does it just sound right?

If the answer is the second one, the sentence gets a hedge or gets deleted.
The full derivation, with the four error classes and the five measures, is in
`PLAN/QG-0001-fruehwarnung.md` in the maintenance repository.
