# Trust Freeze release evidence

What a platform may claim about Trust Freeze, and what backs the claim. The levels are separate statements
and never collapse into one word such as "supported" (SPEC-0471, TF06-R6 and TF06-R7):

| Level | Meaning |
|---|---|
| `implemented` | the code path exists for that platform |
| `fixture-tested` | its parsers and decisions are covered by table tests and fixtures, runnable on any host |
| `cross-compiled` | `go vet` is clean and the test binaries link for that target, nothing was executed there |
| `real-platform-tested` | the test binaries and the acceptance path really ran on that platform, tied to a commit |

Cross-compilation is not a platform test. A run against an earlier commit does not prove a later one.

`release-matrix.json` records, per platform, what actually ran for a given commit: the unit-test totals, the
acceptance script result, and the cross-machine verifications. It carries no host names, addresses or user names:
a bundle does record the host it describes, but this evidence file does not.

The scope of the current entry is the PR-1 walking skeleton: the `common.identity` probe plus the bundle
lifecycle (capture, approve, verify, diff, report). The platform profiles of SPEC-0471 (TF06-R3 to TF06-R5)
are not implemented yet, so TF06-AC1 to TF06-AC4 are not claimed.

Regenerate by running, on each platform, `go test -count=1 ./pkg/skillctl/trustfreeze/... ./cmd/skillctl/` and
`./scripts/trustfreeze-acceptance.sh` against a clean checkout of the commit, then update the entry by hand.
