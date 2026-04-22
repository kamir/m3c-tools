// Package schema defines Go types for every message on every topic
// in the Thinking Engine. Types mirror SPEC/schemas/*.schema.json
// exactly. Every message carries SchemaVer = 1 per D3.
//
// additionalProperties:false in the JSON Schemas means we never add
// struct fields silently — any new field starts in the SPEC.
package schema

import "time"

// CurrentSchemaVer is the canonical schema version produced by this
// build. Bumping this is a source-change, reviewed decision (D3).
const CurrentSchemaVer = 1

// ----- Thought (T) -----

// ThoughtType enumerates SPEC-0167 §Data Model T.type.
type ThoughtType string

const (
	ThoughtFact        ThoughtType = "fact"
	ThoughtObservation ThoughtType = "observation"
	ThoughtQuestion    ThoughtType = "question"
	ThoughtIdea        ThoughtType = "idea"
	ThoughtSignal      ThoughtType = "signal"
	ThoughtFeedback    ThoughtType = "feedback"
)

// SourceKind is the provenance-kind enum for a T.
type SourceKind string

const (
	SourceOCR      SourceKind = "ocr"
	SourceAudio    SourceKind = "audio"
	SourceTyped    SourceKind = "typed"
	SourceImport   SourceKind = "import"
	SourceFeedback SourceKind = "feedback"
	SourceAgent    SourceKind = "agent"
)

// Source is T.source.
type Source struct {
	Kind SourceKind `json:"kind"`
	Ref  string     `json:"ref"`
}

// Location is T.context.location.
type Location struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// TContext is T.context (separate from stdlib context).
type TContext struct {
	ProjectID *string   `json:"project_id,omitempty"`
	Domain    *string   `json:"domain,omitempty"`
	Location  *Location `json:"location,omitempty"`
}

// Provenance is T.provenance.
type Provenance struct {
	CapturedBy       string  `json:"captured_by"`
	ParentArtifactID *string `json:"parent_artifact_id,omitempty"`
}

// Content is a T.content payload. Exactly one of Text/Ref is set.
// Marshal/unmarshal handled by custom methods (see schema_json.go).
type Content struct {
	Text string
	Ref  string
}

// Thought is the T-layer message.
type Thought struct {
	SchemaVer  int         `json:"schema_ver"`
	ThoughtID  string      `json:"thought_id"`
	Type       ThoughtType `json:"type"`
	Content    Content     `json:"content"`
	Source     Source      `json:"source"`
	Tags       []string    `json:"tags,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
	Context    *TContext   `json:"context,omitempty"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

// ----- Reflection (R) -----

type ReflectionStrategy string

const (
	StrategyCompare   ReflectionStrategy = "compare"
	StrategyClassify  ReflectionStrategy = "classify"
	StrategyExplain   ReflectionStrategy = "explain"
	StrategyChallenge ReflectionStrategy = "challenge"
	StrategyClarify   ReflectionStrategy = "clarify"
)

// Tokens mirrors .trace.tokens.
type Tokens struct {
	In  int `json:"in,omitempty"`
	Out int `json:"out,omitempty"`
}

// Trace is the shared prompt/model/tokens record.
type Trace struct {
	PromptID      string  `json:"prompt_id"`
	PromptVersion int     `json:"prompt_version,omitempty"`
	Model         string  `json:"model"`
	Tokens        Tokens  `json:"tokens,omitempty"`
	DurationMS    int     `json:"duration_ms,omitempty"`
	CostUSD       float64 `json:"cost_usd,omitempty"`
}

// Reflection is the R-layer message.
type Reflection struct {
	SchemaVer    int                    `json:"schema_ver"`
	ReflectionID string                 `json:"reflection_id"`
	ThoughtIDs   []string               `json:"thought_ids"`
	Strategy     ReflectionStrategy     `json:"strategy"`
	Objective    string                 `json:"objective,omitempty"`
	Content      map[string]interface{} `json:"content"`
	Trace        Trace                  `json:"trace"`
	Timestamp    time.Time              `json:"timestamp"`
	ProcessID    string                 `json:"process_id,omitempty"`
}

// ----- Insight (I) -----

type SynthesisMode string

const (
	SynthesisPattern       SynthesisMode = "pattern"
	SynthesisContradiction SynthesisMode = "contradiction"
	SynthesisDecision      SynthesisMode = "decision"
	SynthesisAbstraction   SynthesisMode = "abstraction"
)

// Support is one item in I.supporting.
type Support struct {
	Ref    string  `json:"ref"`
	Weight float64 `json:"weight"`
}

// Insight is the I-layer message.
type Insight struct {
	SchemaVer     int                    `json:"schema_ver"`
	InsightID     string                 `json:"insight_id"`
	InputIDs      []string               `json:"input_ids"`
	SynthesisMode SynthesisMode          `json:"synthesis_mode"`
	Content       map[string]interface{} `json:"content"`
	Confidence    float64                `json:"confidence"`
	Supporting    []Support              `json:"supporting,omitempty"`
	Trace         Trace                  `json:"trace"`
	Timestamp     time.Time              `json:"timestamp"`
	ProcessID     string                 `json:"process_id,omitempty"`
}

// ----- Artifact (A) -----

type ArtifactFormat string

const (
	FormatReport     ArtifactFormat = "report"
	FormatSummary    ArtifactFormat = "summary"
	FormatDashboard  ArtifactFormat = "dashboard"
	FormatContent    ArtifactFormat = "content"
	FormatAPIPayload ArtifactFormat = "api_payload"
)

type Audience string

const (
	AudienceHuman  Audience = "human"
	AudienceAgent  Audience = "agent"
	AudienceSystem Audience = "system"
)

// ArtifactProvenance is A.provenance — closure over the cognitive chain.
type ArtifactProvenance struct {
	TIDs []string `json:"t_ids"`
	RIDs []string `json:"r_ids"`
	IIDs []string `json:"i_ids"`
}

// Artifact is the A-layer message. artifacts.created IS truth (D2).
type Artifact struct {
	SchemaVer  int                    `json:"schema_ver"`
	ArtifactID string                 `json:"artifact_id"`
	InsightIDs []string               `json:"insight_ids"`
	Format     ArtifactFormat         `json:"format"`
	Audience   Audience               `json:"audience"`
	Content    map[string]interface{} `json:"content"`
	Version    int                    `json:"version"`
	Provenance ArtifactProvenance     `json:"provenance"`
	Timestamp  time.Time              `json:"timestamp"`
	ProcessID  string                 `json:"process_id,omitempty"`
	ER1Ref     *string                `json:"er1_ref,omitempty"`
}

// ----- ProcessSpec -----

type ProcessMode string

const (
	ModeLinear     ProcessMode = "linear"
	ModeSemiLinear ProcessMode = "semi_linear"
	ModeGuided     ProcessMode = "guided"
	ModeLoop       ProcessMode = "loop"
)

type Layer string

const (
	LayerT Layer = "T"
	LayerR Layer = "R"
	LayerI Layer = "I"
	LayerA Layer = "A"
	LayerC Layer = "C"
)

// StepContextScope is ProcessSpec.steps[].context.scope.
type StepContextScope struct {
	TimeRange []time.Time `json:"time_range,omitempty"`
	Entities  []string    `json:"entities,omitempty"`
	Topics    []string    `json:"topics,omitempty"`
	Projects  []string    `json:"projects,omitempty"`
}

// StepFilters is ProcessSpec.steps[].context.filters.
type StepFilters struct {
	Tags       []string `json:"tags,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
}

// StepConstraints is ProcessSpec.steps[].context.constraints.
type StepConstraints struct {
	MaxItems       int `json:"max_items,omitempty"`
	FreshnessDays  int `json:"freshness_days,omitempty"`
}

// StepContext is ProcessSpec.steps[].context.
type StepContext struct {
	Scope       *StepContextScope `json:"scope,omitempty"`
	Filters     *StepFilters      `json:"filters,omitempty"`
	Constraints *StepConstraints  `json:"constraints,omitempty"`
}

// Step is one element of ProcessSpec.steps.
type Step struct {
	Layer    Layer        `json:"layer"`
	Strategy string       `json:"strategy"`
	Agent    *string      `json:"agent,omitempty"`
	PromptID *string      `json:"prompt_id,omitempty"`
	Model    *string      `json:"model,omitempty"`
	Context  *StepContext `json:"context,omitempty"`
}

type TriggerType string

const (
	TriggerManual   TriggerType = "manual"
	TriggerEvent    TriggerType = "event"
	TriggerSchedule TriggerType = "schedule"
)

// Trigger is one element of ProcessSpec.triggers.
type Trigger struct {
	Type  TriggerType `json:"type"`
	Cron  *string     `json:"cron,omitempty"`
	Event *string     `json:"event,omitempty"`
}

// Callbacks is ProcessSpec.callbacks.
type Callbacks struct {
	OnComplete *string `json:"on_complete,omitempty"`
	OnError    *string `json:"on_error,omitempty"`
}

// Budget is ProcessSpec.budget (D4 per-process cap).
type Budget struct {
	MaxTokens  int     `json:"max_tokens,omitempty"`
	MaxCostUSD float64 `json:"max_cost_usd,omitempty"`
}

// ProcessSpec is the delegation contract the engine executes.
type ProcessSpec struct {
	SchemaVer int         `json:"schema_ver"`
	ProcessID string      `json:"process_id"`
	Intent    string      `json:"intent"`
	Mode      ProcessMode `json:"mode"`
	Depth     int         `json:"depth"`
	Steps     []Step      `json:"steps"`
	Triggers  []Trigger   `json:"triggers,omitempty"`
	Callbacks *Callbacks  `json:"callbacks,omitempty"`
	Budget    *Budget     `json:"budget,omitempty"`
	CreatedAt time.Time   `json:"created_at,omitempty"`
	CreatedBy string      `json:"created_by,omitempty"`
}

// DefaultMaxTokens is D4's per-process hard cap default.
const DefaultMaxTokens = 50000

// EffectiveMaxTokens returns the per-process cap, applying the D4
// default when unset.
func (p ProcessSpec) EffectiveMaxTokens() int {
	if p.Budget != nil && p.Budget.MaxTokens > 0 {
		return p.Budget.MaxTokens
	}
	return DefaultMaxTokens
}

// ----- ProcessEvent (lifecycle) -----

type ProcessEventName string

const (
	EventProcessStarted   ProcessEventName = "ProcessStarted"
	EventStepStarted      ProcessEventName = "StepStarted"
	EventStepCompleted    ProcessEventName = "StepCompleted"
	EventProcessCompleted ProcessEventName = "ProcessCompleted"
	EventProcessFailed    ProcessEventName = "ProcessFailed"
	EventProcessCancelled ProcessEventName = "ProcessCancelled"
)

// ProcessEvent is what lands on process.events.
type ProcessEvent struct {
	SchemaVer  int                    `json:"schema_ver"`
	ProcessID  string                 `json:"process_id"`
	Event      ProcessEventName       `json:"event"`
	StepLayer  *Layer                 `json:"step_layer,omitempty"`
	StepIndex  *int                   `json:"step_index,omitempty"`
	Detail     map[string]interface{} `json:"detail,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// ----- ProcessCommand (process.commands) -----

// ProcessCommand is dispatched by the orchestrator to R/I/A/C procs.
type ProcessCommand struct {
	SchemaVer int         `json:"schema_ver"`
	ProcessID string      `json:"process_id"`
	StepIndex int         `json:"step_index"`
	Step      Step        `json:"step"`
	Spec      ProcessSpec `json:"spec"`
	Timestamp time.Time   `json:"timestamp"`
}
