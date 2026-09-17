# Runbook: the thinking-engine, per-user cognitive runtime

How to build, start, probe and test `cmd/thinking-engine`, the per-user
cognitive runtime of SPEC-0167. Everything below was read from
`cmd/thinking-engine/main.go`, `cmd/thinking-engine/README.md`, the `Makefile`
(`thinking-*` targets) and `internal/thinking/` on 2026-09-16; where the code
and a comment disagree, the code is quoted.

Audience: a developer who wants a running engine on their own machine, or who
has to judge what the binary refuses and why. The index entries are in the
[Program-Index](../../program-index.md) (build), the
[Service-Index](../../service-index.md) (runtime wrapper `deploy/thinking-engine/`)
and the [Component-Index, section G](../../component-index.md) (internals).

Rolle: Entwickler · Sprache: EN · Stand: 2026-09-16

## The one rule the binary enforces at startup

**No user context, no engine.** `--user-context-id` is mandatory; without it
the process prints an error and exits `2`
(`cmd/thinking-engine/main.go`, the first check in `main`). Every later
identifier (topic names, HMAC claims, log prefixes) derives from the hash of
that context. This is SPEC-0167 §Isolation Model as a runtime refusal, not a
convention.

## Start it locally (in-memory bus, no broker)

```bash
make thinking-build
export THINKING_ENGINE_SECRET=dev-secret-please-change
./build/thinking-engine --user-context-id=demo --listen=:7140
curl http://localhost:7140/v1/health
```

Two footnotes, both from `main.go`:

- **The HMAC secret is read from the env var named by `--secret-env`**
  (default `THINKING_ENGINE_SECRET`). If it is empty, the process exits 2
  unless `--dev` is set, in which case main derives a ctx-hash fallback.
- **The LLM wiring of this binary is OpenAI-only.** `main` calls
  `llm.NewOpenAI()` and, when `OPENAI_API_KEY` is unset, logs
  `llm: not configured (...): R/I handlers will fail until configured` and
  keeps running. The richer factory `llm.NewAdapterFromEnv()`
  (OpenAI, else Ollama via `OLLAMA_URL`, optional `M3C_LLM_FALLBACK=ollama`)
  exists in `internal/thinking/llm/llm.go` but is not called by this `main`.

## Flags

Read from the `flag` definitions in `cmd/thinking-engine/main.go`:

| Flag | Purpose |
|---|---|
| `--user-context-id` | REQUIRED; the user context the engine is bound to. Missing: exit `2`. |
| `--listen` | Listen address, default `:7140`. |
| `--secret-env` | Name of the env var holding the HMAC secret, default `THINKING_ENGINE_SECRET`. |
| `--dev` | Allow a ctx-hash HMAC secret when the env var is empty. |
| `--state-path` | SQLite path, default `~/.m3c-tools/thinking/<hash>/state.db`. |
| `--kafka` | Kafka bootstrap address; empty = in-memory bus. Connecting for real needs the `thinking_kafka` build tag. |
| `--er1-credentials` | Path to an ER1 service-account key; the flag's own help text marks it unused in Phase 1. |

## HTTP surface

Routes registered in `internal/thinking/api/` and `main.go`:
`/v1/health`, `/v1/thoughts`, `/v1/process`, `/v1/process/`, `/v1/trace/`,
`/v1/insights`, `/v1/reflections`, `/v1/artifacts`, `/v1/compile`,
`/v1/replay`, `/v1/rebuild`, `/v1/budget/today`, `/v1/budget/history`,
`/metrics`.

## The real broker (build tag `thinking_kafka`)

The franz-go driver lives in `internal/thinking/kafka/bus_franz.go` behind the
`thinking_kafka` build tag; the in-memory driver implements the same `Bus`
interface, so the swap is a build-tag flip:

```bash
export CTX_HASH=$(printf "demo" | shasum -a 256 | cut -c1-16)
make thinking-up            # broker stack
make thinking-topics        # the canonical topics
go build -tags thinking_kafka -o build/thinking-engine ./cmd/thinking-engine
export THINKING_ENGINE_SECRET=dev-secret-please-change
./build/thinking-engine --user-context-id=demo --kafka=localhost:9092 --listen=:7140
```

**Isolation invariant:** every produce and subscribe passes
`assertOwnedBy(topic, owner)` in `internal/thinking/kafka/topics.go`, which
panics on any topic whose prefix does not match the engine's own ctx hash.
Consumer groups are named `m3c-<ctx_hash>-<role>`, so two users' engines on
one broker cannot share a group (`cmd/thinking-engine/README.md`,
"Isolation invariant").

## Tests

```bash
make thinking-test                                           # unit, in-memory bus
M3C_KAFKA_URL=localhost:9092 make thinking-test-integration  # against a real broker
```

Without `M3C_KAFKA_URL` the integration test skips cleanly; that skip is the
CI path for broker-less environments (`cmd/thinking-engine/README.md`).

## Where the rest lives

- Container topology and runtime wrapper: [Service-Index](../../service-index.md),
  `deploy/thinking-engine/`.
- The week-by-week plan and the spec: SPEC-0167 / PLAN-0167 on the private
  maintenance plane, referenced by id (SPEC-0358: a public-plane file carries
  no path into the private one).
