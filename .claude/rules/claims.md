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

## The tools that answer a different question

Every entry below was collected in one week of work in this repository, each one
caught by measurement rather than by reading. They share a shape: **the tool
answers a question next to the one you asked**, and the wrong answer is the
reassuring one.

They split into two kinds, and the second is worse.

**Silent: the tool finds nothing and says nothing.** Silence eventually gets
noticed, because sooner or later somebody expects a hit.

| What was run | The question it really answered | Instead |
|---|---|---|
| `git grep -E '\bname\b'` | none: POSIX ERE has no `\b`, so it matched nothing and exited quietly | `git grep -w name` |
| a YAML loader that tolerates duplicate keys | "can I parse this somehow" | a loader that refuses duplicates; GitHub does |
| a checker resolving a fixed path | "what is checked out in that directory" | name the path, branch and dirty count in the same output |

**False positive: the tool reports success.** A green tick ends the question, so
these run longer before anyone looks.

| What was run | The question it really answered | Instead |
|---|---|---|
| `cmd \| tail -20` in a CI step | "did `tail` succeed" | `shell: bash` (turns on `pipefail`), or drop the pipe |
| `go test -run TestFoo ./pkg/` | "did anything fail": a pattern matching nothing exits 0 | `scripts/require-tests-ran.sh ./pkg/ TestFoo` |
| `gh ... --jq '.field'` compared to `"null"` | nothing: jq prints EMPTY for a null field, never the word | `--jq '(.field != null)'`, then compare to `true` |
| an unquoted `$var` in a `for` loop under zsh | "one iteration for the whole string" | quote it, or run the loop under `bash` |

Every row was measured on this repository rather than recalled. Three of them,
verbatim:

    git grep -E '\bkamir\b' -- '*.md'   ->   0 files
    git grep -w  'kamir'      -- '*.md'   ->  49 files

    zsh  -c 'v="a b c"; for x in $v; ...'  ->  1 iteration
    bash -c 'v="a b c"; for x in $v; ...'  ->  3 iterations

    go test -count=1 -run TestDoesNotExist ./pkg/er1/
    ok  github.com/kamir/m3c-tools/pkg/er1  0.209s [no tests to run]   exit=0

The third one deserves a second look, because Go is not hiding anything: it
prints `[no tests to run]`. The information is in the text and never in the exit
code, and CI reads the exit code. A tool can be honest in prose and still make a
gate lie, which is why the wrapper checks for run events instead of reading the
summary line.

The `jq` entry is the worst of the set and it is worth saying why. It sat inside
the automation written to catch exactly this class, and it failed in both
directions at once: it raised an alarm in the correct state and printed
"Verified" in the wrong one. A checker that answers wrongly is worse than none,
because it manufactures confidence the state does not support. That is the
mirror of "a gate that does not run rots in both directions": a gate that runs
and answers wrongly does more damage than one that is missing.

**How to use this table.** Not as a list to memorise. Before trusting any green
result, ask the one question that generated every row: *which question did this
command actually answer?* Then, if the answer could be "none" or "something
adjacent", prove it against a planted hit, which is rule 4.

## An insight prevents nothing; write the rule instead

One entry in this table was recorded as a lesson, agreed with, and then repeated
an hour later by the same reader. The lesson had been phrased as an insight: "an
author name is not a source of authorship". True, and useless in the moment,
because there is nothing to follow or break.

What replaced it is a rule with an observable action: **never name a pull
request, branch or commit with an owner.** Write "PR #263", not "your #263". Who
is working on what is known only when a session says so itself.

The difference generalises. An insight describes a shape; a rule names a thing
you do or do not do, and its violation is visible in the text you just wrote.
Everything in this file is phrased that way on purpose, and anything added later
should be too. If a new lesson cannot be written as an action, it is not ready.

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
