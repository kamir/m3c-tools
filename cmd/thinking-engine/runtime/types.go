package runtime

import (
	"context"
	"time"
)

// InvocationEventType enumerates the SPEC-0202 §9 event_type values
// that this package projects from the Kafka invocation stream.
type InvocationEventType string

const (
	EventCapabilityIssued    InvocationEventType = "capability.issued"
	EventCapabilityAttenuated InvocationEventType = "capability.attenuated"
	EventCapabilityRevoked   InvocationEventType = "capability.revoked"
	EventGateAllowed         InvocationEventType = "gate.allowed"
	EventGateRefused         InvocationEventType = "gate.refused"
	EventInvocationCompleted InvocationEventType = "invocation.completed"
)

// InvocationEvent mirrors the SPEC-0202 §9 Avro shapes, deserialized.
// The watcher reads these from the tenant-scope topic
// `m3c.<tenant>.skill_invocations`.
//
// Not every field is populated for every event_type — see SPEC-0202 §9
// and the per-event projection rules in SPEC-0167 A.3.
type InvocationEvent struct {
	EventType    InvocationEventType `json:"event_type"`
	OccurredAt   time.Time           `json:"occurred_at"`

	// Identity / scope
	TokenID         string `json:"token_id"`
	ParentTokenID   string `json:"parent_token_id,omitempty"`
	BundleDigest    string `json:"bundle_digest,omitempty"`
	SkillName       string `json:"skill_name,omitempty"`
	SkillVersion    string `json:"skill_version,omitempty"`
	Tenant          string `json:"tenant"`
	CallerIdentity  string `json:"caller_identity"`
	CallerSession   string `json:"caller_session,omitempty"`

	// Gate-specific (gate.allowed / gate.refused)
	Surface  string `json:"surface,omitempty"`  // e.g. "http_get", "subprocess_run"
	Target   string `json:"target,omitempty"`   // URL, argv, path
	ExitCode int    `json:"exit_code,omitempty"` // populated on gate.refused
	RuleHit  string `json:"rule_hit,omitempty"`  // e.g. "egress_host_not_allowed"

	// Invocation-completed-specific
	ExitStatus    string `json:"exit_status,omitempty"` // ok | fail | killed
	WallClockMS   int    `json:"wall_clock_ms,omitempty"`
	EgressBytes   int64  `json:"egress_bytes,omitempty"`

	// Attenuation-specific
	AttenuationRule  string      `json:"rule,omitempty"`
	AttenuationValue interface{} `json:"value,omitempty"`
	AppliedBy        string      `json:"applied_by,omitempty"`

	// Revoke-specific
	RevokedBy     string `json:"revoked_by,omitempty"`
	RevokedReason string `json:"reason,omitempty"`

	// Per-event signature; producer key bound at SPEC-0188 identity time.
	// The watcher may verify (defense in depth) but the topic ACL is the
	// primary integrity control — only the registry and per-host gateways
	// can produce.
	SignatureB64 string `json:"signature_b64,omitempty"`
}

// Thought is the v1 T-schema target shape this package projects to.
// See SPEC/schemas/T.schema.json and SPEC-0167 §T-layer.
//
// We deliberately reuse `source.kind: "agent"` and structured `content`
// rather than introducing a new T-schema kind — the amendment (A.7) is
// non-breaking by design; a future T-schema v2 may add a dedicated
// `runtime_invocation` kind.
type Thought struct {
	SchemaVer  int               `json:"schema_ver"` // const 1
	ThoughtID  string            `json:"thought_id"` // UUIDv7
	Type       ThoughtType       `json:"type"`
	Content    interface{}       `json:"content"` // structured object for runtime
	Source     ThoughtSource     `json:"source"`
	Tags       []string          `json:"tags,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
	Context    *ThoughtContext   `json:"context,omitempty"`
	Provenance ThoughtProvenance `json:"provenance"`
}

type ThoughtType string

const (
	ThoughtSignal      ThoughtType = "signal"
	ThoughtObservation ThoughtType = "observation"
	ThoughtFeedback    ThoughtType = "feedback"
	// fact, question, idea exist in the T enum but are not produced by
	// the runtime watcher.
)

type ThoughtSource struct {
	Kind string `json:"kind"` // always "agent" for runtime-projected thoughts
	Ref  string `json:"ref"`  // skill-invocation://<tenant>/<token_id>
}

type ThoughtContext struct {
	ProjectID string `json:"project_id,omitempty"`
	Domain    string `json:"domain,omitempty"` // tenant id (A.2 isolation invariant)
}

type ThoughtProvenance struct {
	CapturedBy        string `json:"captured_by"`           // "runtime-invocation-watcher/v1"
	ParentArtifactID  string `json:"parent_artifact_id"`    // bundle_digest (A.3 graph edge)
}

// Reflection is the v1 R-schema target shape the reflectors emit.
// See SPEC/schemas/R.schema.json and SPEC-0167 §R-layer.
//
// In v1 the runtime reflectors emit strategy="classify" with
// objective="runtime_pattern_detection" — A.4. R-schema v2 may add a
// dedicated `runtime_pattern` strategy; that bump is out of scope for
// this amendment.
type Reflection struct {
	SchemaVer    int                    `json:"schema_ver"` // const 1
	ReflectionID string                 `json:"reflection_id"`
	ThoughtIDs   []string               `json:"thought_ids"`
	Strategy     string                 `json:"strategy"`            // "classify" in v1
	Objective    string                 `json:"objective,omitempty"` // "runtime_pattern_detection"
	Content      map[string]interface{} `json:"content"`
	Trace        ReflectionTrace        `json:"trace"`
	Timestamp    time.Time              `json:"timestamp"`
	ProcessID    string                 `json:"process_id,omitempty"`
}

type ReflectionTrace struct {
	PromptID      string  `json:"prompt_id"`
	PromptVersion int     `json:"prompt_version,omitempty"`
	Model         string  `json:"model"` // "rule:refusal-cluster/v1" for non-LLM reflectors
	DurationMS   int     `json:"duration_ms,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
}

// Reflector is the contract that refusal_cluster, egress_anomaly, and
// token_lifetime_shape implement. Each reflector:
//   - receives the projected stream of Thoughts (from the watcher),
//   - maintains internal sliding-window or histogram state,
//   - emits zero-or-more Reflections via Emit when its trigger fires.
//
// Reflectors are stateful but per-context-isolated; the watcher
// instantiates a fresh set per (tenant, ctx) pair.
type Reflector interface {
	// Name returns a stable identifier for prompts/audit (e.g.
	// "refusal-cluster"). Used in trace.model = "rule:<name>/v1".
	Name() string

	// Observe is called for every projected Thought. Reflectors that
	// don't care about a given Thought (wrong source.kind, wrong type)
	// MUST return without doing work — Observe is on the hot path.
	Observe(ctx context.Context, t Thought) error

	// Tick is called on a periodic timer (1m default) and lets
	// reflectors emit window-bounded Reflections without depending on
	// observation-time triggers. token_lifetime_shape uses Tick.
	Tick(ctx context.Context, now time.Time) error

	// Drain produces any pending Reflections at shutdown so we don't
	// lose state. Implementations MAY return an empty slice.
	Drain(ctx context.Context) ([]Reflection, error)
}

// ReflectionEmitter is what reflectors call to publish a Reflection
// onto the engine's per-context reflections topic. The watcher injects
// an implementation that writes to
// `m3c.<ctx_hash>.reflections.generated` — reflectors NEVER write
// directly to Kafka.
type ReflectionEmitter interface {
	Emit(ctx context.Context, r Reflection) error
}

// EventConsumer abstracts the Kafka subscription for the tenant-scope
// invocation topic. Implementations bind to segmentio/kafka-go or
// franz-go at wire time; the watcher itself stays client-agnostic so
// tests can drive it from a slice.
type EventConsumer interface {
	// Next blocks until an event is available or ctx is cancelled.
	Next(ctx context.Context) (InvocationEvent, error)

	// Close releases the subscription.
	Close() error
}

// ThoughtPublisher abstracts the per-context Kafka producer that
// writes onto `m3c.<ctx_hash>.thoughts.raw`. Same rationale as
// EventConsumer — the watcher does not pin a Kafka client.
type ThoughtPublisher interface {
	Publish(ctx context.Context, t Thought) error
	Close() error
}
