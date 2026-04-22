// validation.go — JSON Schema validators for every Kafka payload.
//
// SPEC-0167 §Data Model requires every produced message to validate
// against its JSON Schema before it hits the wire, and every consumed
// message to validate before dispatch to a handler. This file owns
// that contract: it compiles the five schema files from
// SPEC/schemas/ once at process start, and exposes a typed
// ValidatingBus wrapper + SchemaValidationError.
//
// Malformed messages are REJECTED with a typed error — no silent
// drops anywhere in the hot path.
package kafka

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schemas/*.schema.json
var embeddedSchemas embed.FS

// SchemaName identifies which schema a payload must validate against.
// It maps 1:1 to the SPEC/schemas/*.schema.json files.
type SchemaName string

const (
	SchemaT           SchemaName = "T"
	SchemaR           SchemaName = "R"
	SchemaI           SchemaName = "I"
	SchemaA           SchemaName = "A"
	SchemaProcessSpec SchemaName = "ProcessSpec"
)

// AllSchemas is the canonical list.
func AllSchemas() []SchemaName {
	return []SchemaName{SchemaT, SchemaR, SchemaI, SchemaA, SchemaProcessSpec}
}

// SchemaValidationError is returned when a payload fails JSON Schema
// validation. It wraps the underlying cause with enough context to
// trace which schema rejected which message.
type SchemaValidationError struct {
	Schema SchemaName
	Topic  string
	Key    string
	Cause  error
}

// Error implements the error interface.
func (e *SchemaValidationError) Error() string {
	base := fmt.Sprintf("schema validation failed: schema=%s", e.Schema)
	if e.Topic != "" {
		base += " topic=" + e.Topic
	}
	if e.Key != "" {
		base += " key=" + e.Key
	}
	if e.Cause != nil {
		base += ": " + e.Cause.Error()
	}
	return base
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e *SchemaValidationError) Unwrap() error { return e.Cause }

// IsSchemaValidationError reports whether err (or anything it wraps)
// is a *SchemaValidationError.
func IsSchemaValidationError(err error) bool {
	var s *SchemaValidationError
	return errors.As(err, &s)
}

// ValidatorMetrics is a lightweight counter surface so operators can
// see per-schema produce/consume/fail counts without pulling in a
// full metrics lib for Phase 1.
type ValidatorMetrics struct {
	produced map[SchemaName]*atomic.Uint64
	consumed map[SchemaName]*atomic.Uint64
	rejected map[SchemaName]*atomic.Uint64
}

func newMetrics() *ValidatorMetrics {
	m := &ValidatorMetrics{
		produced: make(map[SchemaName]*atomic.Uint64),
		consumed: make(map[SchemaName]*atomic.Uint64),
		rejected: make(map[SchemaName]*atomic.Uint64),
	}
	for _, s := range AllSchemas() {
		m.produced[s] = new(atomic.Uint64)
		m.consumed[s] = new(atomic.Uint64)
		m.rejected[s] = new(atomic.Uint64)
	}
	return m
}

// Produced returns how many messages passed produce-side validation
// for the given schema.
func (m *ValidatorMetrics) Produced(s SchemaName) uint64 {
	if c, ok := m.produced[s]; ok {
		return c.Load()
	}
	return 0
}

// Consumed returns how many messages passed consume-side validation.
func (m *ValidatorMetrics) Consumed(s SchemaName) uint64 {
	if c, ok := m.consumed[s]; ok {
		return c.Load()
	}
	return 0
}

// Rejected returns how many messages (produce or consume side) failed
// validation.
func (m *ValidatorMetrics) Rejected(s SchemaName) uint64 {
	if c, ok := m.rejected[s]; ok {
		return c.Load()
	}
	return 0
}

// Validator compiles and owns all five schemas. It's safe for
// concurrent use.
type Validator struct {
	schemas map[SchemaName]*jsonschema.Schema
	metrics *ValidatorMetrics
}

var defaultValidator struct {
	once sync.Once
	v    *Validator
	err  error
}

// DefaultValidator returns a process-wide Validator compiled from the
// embedded SPEC/schemas/ files. First call compiles; subsequent calls
// return the cached instance.
func DefaultValidator() (*Validator, error) {
	defaultValidator.once.Do(func() {
		defaultValidator.v, defaultValidator.err = NewValidatorFromEmbed()
	})
	return defaultValidator.v, defaultValidator.err
}

// NewValidatorFromEmbed compiles the validator from the embedded
// schema FS. Exposed for tests that want a fresh instance.
func NewValidatorFromEmbed() (*Validator, error) {
	return newValidatorFromFS(embeddedSchemas, "schemas")
}

func newValidatorFromFS(fsys fs.FS, dir string) (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020

	v := &Validator{
		schemas: make(map[SchemaName]*jsonschema.Schema),
		metrics: newMetrics(),
	}

	for _, s := range AllSchemas() {
		path := fmt.Sprintf("%s/%s.schema.json", dir, s)
		f, err := fsys.Open(path)
		if err != nil {
			return nil, fmt.Errorf("validator: open %s: %w", path, err)
		}
		body, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("validator: read %s: %w", path, err)
		}
		// Use the schema's own $id as resource URL for clarity in
		// error messages.
		if err := compiler.AddResource(string(s), strings.NewReader(string(body))); err != nil {
			return nil, fmt.Errorf("validator: add %s: %w", s, err)
		}
		sc, err := compiler.Compile(string(s))
		if err != nil {
			return nil, fmt.Errorf("validator: compile %s: %w", s, err)
		}
		v.schemas[s] = sc
	}
	return v, nil
}

// Metrics returns the counter surface.
func (v *Validator) Metrics() *ValidatorMetrics { return v.metrics }

// Validate runs the named schema against raw JSON bytes. Returns a
// *SchemaValidationError on failure.
func (v *Validator) Validate(s SchemaName, body []byte) error {
	sc, ok := v.schemas[s]
	if !ok {
		return fmt.Errorf("validator: unknown schema %q", s)
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return &SchemaValidationError{Schema: s, Cause: fmt.Errorf("invalid json: %w", err)}
	}
	if err := sc.Validate(doc); err != nil {
		return &SchemaValidationError{Schema: s, Cause: err}
	}
	return nil
}

// SchemaForSuffix picks the right schema for a topic suffix. Returns
// empty string for topics that do not have a schema gate (e.g.
// process.commands, process.events — those are internal to the
// engine and have their own Go types, not externally-validated).
func SchemaForSuffix(suffix TopicSuffix) SchemaName {
	switch suffix {
	case TopicThoughtsRaw:
		return SchemaT
	case TopicReflectionsGenerated:
		return SchemaR
	case TopicInsightsGenerated:
		return SchemaI
	case TopicArtifactsCreated:
		return SchemaA
	}
	return ""
}

// SchemaForTopic resolves a full topic name (e.g. "m3c.<hash>.thoughts.raw")
// to its SchemaName. Returns "" if the topic has no schema gate.
func SchemaForTopic(topic string) SchemaName {
	// The suffix is everything after "m3c.<hash>.".
	// We don't need to parse the hash — just match the known suffixes.
	for _, s := range AllTopics() {
		if strings.HasSuffix(topic, "."+string(s)) {
			return SchemaForSuffix(s)
		}
	}
	return ""
}

// ----- ValidatingBus wrapper -----

// ValidatingBus wraps another Bus and validates every payload on
// produce and every delivered payload on consume. Topics with no
// schema gate (see SchemaForTopic) pass through unchanged.
type ValidatingBus struct {
	inner Bus
	v     *Validator
}

// NewValidatingBus wraps b with validation. If v is nil, the default
// embedded validator is used.
func NewValidatingBus(b Bus, v *Validator) (*ValidatingBus, error) {
	if v == nil {
		var err error
		v, err = DefaultValidator()
		if err != nil {
			return nil, err
		}
	}
	return &ValidatingBus{inner: b, v: v}, nil
}

// Produce validates value against the topic's schema (if any), then
// delegates to the inner Bus. On validation failure, returns a
// *SchemaValidationError and does NOT produce.
func (b *ValidatingBus) Produce(ctx context.Context, topic string, key string, value any) error {
	sch := SchemaForTopic(topic)
	if sch == "" {
		return b.inner.Produce(ctx, topic, key, value)
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("validatingbus: marshal: %w", err)
	}
	if err := b.v.Validate(sch, body); err != nil {
		if svErr, ok := err.(*SchemaValidationError); ok {
			svErr.Topic = topic
			svErr.Key = key
			b.v.metrics.rejected[sch].Add(1)
		}
		return err
	}
	b.v.metrics.produced[sch].Add(1)
	// Pass the pre-marshaled bytes through as RawMessage so the inner
	// bus does not re-marshal and drift from what we validated.
	return b.inner.Produce(ctx, topic, key, json.RawMessage(body))
}

// Subscribe installs a wrapper handler that validates before dispatch.
// Validation failures are reported via errors.Join-style wrapping so
// the caller sees a typed *SchemaValidationError and no handler fires.
func (b *ValidatingBus) Subscribe(topic string, h Handler) (func(), error) {
	sch := SchemaForTopic(topic)
	wrapped := h
	if sch != "" {
		wrapped = func(ctx context.Context, m Message) error {
			if err := b.v.Validate(sch, m.Value); err != nil {
				if svErr, ok := err.(*SchemaValidationError); ok {
					svErr.Topic = topic
					svErr.Key = string(m.Key)
					b.v.metrics.rejected[sch].Add(1)
				}
				return err
			}
			b.v.metrics.consumed[sch].Add(1)
			return h(ctx, m)
		}
	}
	return b.inner.Subscribe(topic, wrapped)
}

// Close delegates to the inner bus.
func (b *ValidatingBus) Close() error { return b.inner.Close() }

// Metrics exposes the underlying validator's counters.
func (b *ValidatingBus) Metrics() *ValidatorMetrics { return b.v.metrics }

// Inner returns the wrapped Bus. Used by tests.
func (b *ValidatingBus) Inner() Bus { return b.inner }
