# Prose style for agents working in this repository

Read this **before** writing, not after. It is one rule, and it is checked by a
`PreToolUse` hook that will refuse the write if you get it wrong.

## The rule

Never emit the character U+2014 EM DASH. Not in code, comments, doc comments,
Markdown, YAML, shell, HTML, SVG, JSON, commit messages, PR bodies, issue text,
CLI output, error strings, or anything you hand back to the user in chat.

Also do not reach for its usual disguises: a spaced hyphen (` - `) doing the job
of a dash, or a double hyphen (` -- `). Those are the same habit wearing a
different glyph. Pick real punctuation.

## What to write instead

Decide what the two halves of the sentence are doing to each other, then punctuate:

| Relationship | Mark | Written out |
|---|---|---|
| A label and its expansion | `:` | `Command surface: authoring, trust, install` |
| Two independent statements | `.` | `The gate is blocking. A failure stops the release.` |
| Two clauses too close to split | `;` | `no admin rights; the machine-wide installer differs` |
| An aside inside one sentence | `, ,` or `( )` | `The seam, on the hot path, is stateless` |
| A continuation or afterthought | `,` | `signed, not merely checksummed` |
| An empty cell in a table | `n/a` | a cell holding only a dash becomes `n/a` |

If none of those fit, the sentence is doing two jobs. Split it.

## Why this is a rule and not a preference

1. The em dash is the clearest stylistic tell of machine-written text. This
   repository ships a trust and provenance story; prose that reads as generated
   costs it credibility before a reader reaches the code.
2. The dash is a placeholder for a decision you have not made yet. Choosing the
   colon, the period or the comma forces the sentence to say which relationship
   it means, and the result is better technical prose almost every time.

## Context traps

- **YAML**: a `:` dropped into an unquoted scalar changes the document
  structure. Quote the value (`name: "Guard: refs are pinned"`) or use a comma.
- **Strings under test**: changing a message in `cmd/` or `pkg/` means changing
  the assertion too, and a `.` capitalises the next word. Prefer `;` or `,`
  inside strings that a test pins.
- **Markdown tables**: a lone dash in a cell means "not applicable". Write `n/a`.
- **Go doc comments**: `// Foo does X: it never does Y.` A colon reads better
  than a dash and matches the rest of the tree.

## Verifying

```bash
./scripts/check-no-emdash.sh            # whole tree, exit 1 on any hit
./scripts/check-no-emdash.sh --staged   # only what you are about to commit
```

The full rationale, the exemption list and the CI wiring are in
[CODESTYLE.md](../../CODESTYLE.md#prose-no-em-dashes).
