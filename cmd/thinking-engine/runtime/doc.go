// Package runtime is the thinking-engine sub-component that consumes
// the SPEC-0202 capability-token invocation stream and projects it
// into the user's T/R/I/A pipeline.
//
// SPEC source of truth:
//   - SPEC-0167 §"Amendment 2026-05-06 — SPEC-0202 Invocation-Stream
//     Consumption" (sections A.1–A.10) — the contract this package
//     implements. Consult that amendment FIRST when changing behavior;
//     code drift from the SPEC is a bug.
//   - SPEC-0202 §9 — invocation event Avro schemas (the producer side).
//   - SPEC-0202 §4.1 + SPEC/schemas/skill-capability-v1.json — the
//     capability-token shape. The watcher does not parse tokens itself;
//     it consumes events about them.
//
// Architectural constraints (MUSTs from SPEC-0167 A.2):
//
//  1. Filter, don't fan in. The watcher subscribes to a tenant-scope
//     Kafka topic carrying ALL users in that tenant. It MUST filter by
//     caller_identity == this engine's user_context_id BEFORE projecting
//     into the Thought stream. Cross-user leak here is a P0 incident.
//
//  2. Tenant ≠ context. One user may belong to several tenants; this
//     package supports N (tenant, ctx) subscriptions funneling into the
//     SAME single m3c.<ctx_hash>.thoughts.raw topic. The originating
//     tenant lands in Thought.context.domain.
//
//  3. Loopback only. Read from the tenant-scope cluster (per
//     SPEC-0193); write to the engine's own per-context cluster. Never
//     produce events back onto the tenant-scope cluster — the watcher
//     is one-way (consume in, project local, write local).
//
// Phase mapping (SPEC-0167 A.8):
//   Step 1 → watcher.go  (filter + project)
//   Step 2 → refusal_cluster.go, egress_anomaly.go, token_lifetime_shape.go
//   Step 3 → backpressure + sampling logic in watcher.go
//   Step 4 → integration tests (separate file: watcher_integration_test.go)
//   Step 5 → T-schema v2 proposal note (DRAFT only, no schema bump)
//
// All files in this package are stubs — types and signatures land the
// contract, function bodies are TODOs. Implementation kicks off as
// SPEC-0202 Phase 5.
package runtime
