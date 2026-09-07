# Cross-version wire-format fixtures

Frozen bytes written by an **older released** `skillctl`, kept so the current
build can prove it still reads them. Do not regenerate them to make a test pass:
a red test here is a compatibility break in the code, not a stale fixture.

| File | Produced by | Contains |
|---|---|---|
| `skillctl-v0.4.0-registry.bundle` | tag `skillctl/v0.4.0` (commit `f43eb49`) | a `local://` registry with `wire-freeze-canary@1.0.0`: the signed `.skb`, its `BundleAdmittedEvent` and its `AttestationPublishedEvent` |

The consumer, the pins, and the exact recipe for producing a new fixture are all
in the doc comment of [`../../wire_format_compat_test.go`](../../wire_format_compat_test.go).
