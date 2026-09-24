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

`release-matrix.json` records, per ROUND and per platform, what actually ran for a given commit: the unit-test
totals, the acceptance script result, the cross-machine verifications, and for a round with real captures the
probe outcomes and what the runs found. It carries no host names, addresses or user names: a bundle does record
the host it describes, but this evidence file does not.

A round also lists `defects_found_by_these_runs`. That list is the argument for running on real hosts at all: the
T-03 round found six defects that 49 fixtures and three review passes had not, among them a redaction marker that
broke colon separated records and dropped the root account from the bundle.

Scope of the two rounds recorded today: T-01 is the walking skeleton (the `common.identity` probe plus the
bundle lifecycle). T-03 adds the nine Linux probes and the `ubuntu-bastion` profile, executed on two real Ubuntu
hosts, one of them a bastion. TF06-AC1 (a real Linux run of the required probes) is therefore claimed for the
Linux round; TF06-AC2 (Windows and WSL) and TF06-AC3 (macOS probe families) are NOT, because those probe
families do not exist. TF06-AC4 (cross-machine verification) is claimed for both rounds.

Not yet implemented, and therefore not claimed for the Ubuntu bastion profile: routes and DNS state, and the
hash of the executable behind a service. Until both exist, a `complete` capture means complete against the
profile as it stands, not against the full list in SPEC-0471 TF06-R3.

Regenerate by running, on each platform, `go test -count=1 ./pkg/skillctl/trustfreeze/... ./cmd/skillctl/` and
`./scripts/trustfreeze-acceptance.sh` against a clean checkout of the commit, then update the entry by hand.
