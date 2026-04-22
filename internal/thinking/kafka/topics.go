// Package kafka wraps the Kafka producer/consumer used by the
// Thinking Engine. SPEC-0167 locks franz-go (pure Go, no CGO) as
// the production client. For Phase 1 Week 1 we expose a Bus
// interface and ship two drivers:
//
//   - memBus (default, always built): in-process channel-backed
//     bus for local development and unit tests. No broker needed.
//     Used when integration tests run under `go test -short`.
//
//   - franzBus (build tag `thinking_kafka`): real franz-go client.
//     Compile with `go build -tags thinking_kafka` to opt in.
//
// The producer enforces the SPEC-0167 §Isolation Model rule at
// runtime: any topic name whose prefix does not match the engine's
// own ctx hash panics. This is NOT advisory. It is the operational
// guard that makes the per-user-cluster story survive misconfigured
// code.
package kafka

import (
	"fmt"
	"strings"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// TopicSuffix is the event-class portion of a topic name, appended
// to "m3c.<hash>.". Declared as constants so consumers cannot typo
// a topic.
type TopicSuffix string

const (
	TopicThoughtsRaw          TopicSuffix = "thoughts.raw"
	TopicReflectionsGenerated TopicSuffix = "reflections.generated"
	TopicInsightsGenerated    TopicSuffix = "insights.generated"
	TopicArtifactsCreated     TopicSuffix = "artifacts.created"
	TopicProcessCommands      TopicSuffix = "process.commands"
	TopicProcessEvents        TopicSuffix = "process.events"
	TopicCompilationRequests  TopicSuffix = "compilation.requests"
	TopicContextSnapshots     TopicSuffix = "context.snapshots"
)

// AllTopics is the canonical list used by topic-bootstrap.sh.
func AllTopics() []TopicSuffix {
	return []TopicSuffix{
		TopicThoughtsRaw,
		TopicReflectionsGenerated,
		TopicInsightsGenerated,
		TopicArtifactsCreated,
		TopicProcessCommands,
		TopicProcessEvents,
		TopicCompilationRequests,
		TopicContextSnapshots,
	}
}

// TopicName joins a hash with a suffix into the full "m3c.<hash>.<suffix>".
func TopicName(h mctx.Hash, s TopicSuffix) string {
	return h.TopicPrefix() + string(s)
}

// assertOwnedBy panics if topic does not start with the engine's own
// hash prefix. This is the hard runtime check described in the SPEC.
// Callers MUST route every produce/consume through it.
func assertOwnedBy(topic string, owner mctx.Hash) {
	prefix := owner.TopicPrefix()
	if !strings.HasPrefix(topic, prefix) {
		panic(fmt.Sprintf(
			"thinking/kafka: FATAL cross-tenant topic access "+
				"(topic=%q owner_prefix=%q); this is a compile/config bug, "+
				"refusing to proceed — SPEC-0167 §Isolation Model",
			topic, prefix,
		))
	}
}
