# thinking-engine

Per-user cognitive runtime for SPEC-0167. Refuses to start without
`--user-context-id`.

## Run locally for one user

```bash
make thinking-build
export THINKING_ENGINE_SECRET=dev-secret-please-change
./build/thinking-engine --user-context-id=demo --listen=:7140
curl http://localhost:7140/v1/health     # returns ctx hash
```

Week 1 uses an in-memory Kafka bus and a stubbed ER1 client — no
broker required. See PLAN-0167 for the week-by-week roadmap.
