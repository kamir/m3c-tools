# thinking-engine

Per-user cognitive runtime for SPEC-0167. Refuses to start without
`--user-context-id`.

## Run locally for one user (default: in-memory bus, no broker)

```bash
make thinking-build
export THINKING_ENGINE_SECRET=dev-secret-please-change
./build/thinking-engine --user-context-id=demo --listen=:7140
curl http://localhost:7140/v1/health     # returns ctx hash
```

Week 1 ships an in-memory Kafka bus and a stubbed ER1 client — no
broker required. See PLAN-0167 for the week-by-week roadmap.

## Run with the real broker (`thinking_kafka` build tag, Stream 2c)

The real franz-go driver lives in
`internal/thinking/kafka/bus_franz.go` behind the `thinking_kafka`
build tag. It implements the same `Bus` interface as the in-memory
driver; swapping between the two is a build-tag flip, not a code
change.

### 1. Bring up the cp-all-in-one broker stack

```bash
export CTX_HASH=$(printf "demo" | shasum -a 256 | cut -c1-16)
make thinking-up            # zookeeper + broker + schema-registry + control-center
make thinking-topics        # create the 8 canonical topics
```

### 2. Build the engine image (optional — only needed for container runs)

```bash
make thinking-image         # tags m3c/thinking-engine:dev
```

### 3. Run the engine, pointed at the broker

Native binary (faster iteration):

```bash
# Compile with the real driver wired in.
go build -tags thinking_kafka -o build/thinking-engine ./cmd/thinking-engine
export THINKING_ENGINE_SECRET=dev-secret-please-change
./build/thinking-engine \
  --user-context-id=demo \
  --kafka=localhost:9092 \
  --listen=:7140
```

Containerized (matches production topology):

```bash
export CTX_HASH=$(printf "demo" | shasum -a 256 | cut -c1-16)
export M3C_USER_CONTEXT_ID=demo
export THINKING_ENGINE_SECRET=dev-secret-please-change
docker compose -f deploy/thinking-engine/docker-compose.yml --profile engine up -d
```

### 4. Run the tagged integration test

```bash
M3C_KAFKA_URL=localhost:9092 make thinking-test-integration
```

Without `M3C_KAFKA_URL` the test skips cleanly — this is the CI path
for environments that don't have a broker available.

## Isolation invariant

Every produce and subscribe goes through `assertOwnedBy(topic, owner)`
in `internal/thinking/kafka/topics.go`, which panics on any topic
whose prefix does not match the engine's own ctx hash. This is a
runtime guard, not a lint — SPEC-0167 §Isolation Model makes it
operational, not advisory. The franz-go driver inherits this guard
unchanged.

Consumer groups are named `m3c-<ctx_hash>-<role>` (dots in the topic
suffix become dashes, e.g. `thoughts.raw` → `thoughts-raw`). Two
users' engines pointed at the same broker still cannot share a group.
