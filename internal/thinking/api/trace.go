// trace.go — provenance-tree walker for GET /v1/trace/{artifact_id}.
//
// SPEC-0167 §Service Components §internal/api + OpenAPI schema
// require a TraceNode tree:
//
//	TraceNode { layer, id, summary, children }
//
// The walker reads the A from the cache, then recursively looks up
// the I/R/T messages it references via provenance + input/thought_id
// arrays. Missing intermediate nodes are surfaced as leaves with a
// `summary: "missing"` marker — never as a crash — per Stream 3b's
// acceptance criteria.
package api

import (
	"encoding/json"
	"strings"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// traceNode is the wire-format for /v1/trace responses.
type traceNode struct {
	Layer    string      `json:"layer"`
	ID       string      `json:"id"`
	Summary  string      `json:"summary"`
	Error    string      `json:"error,omitempty"`
	Children []traceNode `json:"children"`
}

// summaryMaxLen caps how many content characters we echo per T node.
const summaryMaxLen = 80

// buildTrace assembles the tree rooted at the given artifact.
// Returns ok=false if the artifact itself cannot be found.
func buildTrace(cache *store.Cache, artifactID string) (traceNode, bool) {
	if cache == nil || artifactID == "" {
		return traceNode{}, false
	}
	payload := cache.Get("A", artifactID)
	if payload == nil {
		return traceNode{}, false
	}
	var art map[string]interface{}
	if err := json.Unmarshal(payload, &art); err != nil {
		return traceNode{
			Layer: "A", ID: artifactID, Error: "malformed",
			Summary: "[malformed]", Children: []traceNode{},
		}, true
	}
	// Root A node.
	node := traceNode{
		Layer:    "A",
		ID:       artifactID,
		Summary:  summariseArtifact(art),
		Children: []traceNode{},
	}

	// Children are Insights referenced via provenance.i_ids (primary)
	// or insight_ids (fallback). Walk each one.
	seen := map[string]bool{}
	for _, iid := range artifactInsightIDs(art) {
		if seen[iid] {
			continue
		}
		seen[iid] = true
		node.Children = append(node.Children, walkInsight(cache, iid))
	}
	return node, true
}

// walkInsight returns a TraceNode for an I message, recursing into its
// input_ids — which can point to R and/or T messages.
func walkInsight(cache *store.Cache, insightID string) traceNode {
	payload := cache.Get("I", insightID)
	if payload == nil {
		return traceNode{Layer: "I", ID: insightID, Summary: "[missing]", Error: "missing", Children: []traceNode{}}
	}
	var ins map[string]interface{}
	if err := json.Unmarshal(payload, &ins); err != nil {
		return traceNode{Layer: "I", ID: insightID, Summary: "[malformed]", Error: "malformed", Children: []traceNode{}}
	}
	n := traceNode{
		Layer:    "I",
		ID:       insightID,
		Summary:  summariseInsight(ins),
		Children: []traceNode{},
	}
	seen := map[string]bool{}
	for _, inputID := range stringSlice(ins["input_ids"]) {
		if seen[inputID] {
			continue
		}
		seen[inputID] = true
		n.Children = append(n.Children, walkReflectionOrThought(cache, inputID))
	}
	return n
}

// walkReflectionOrThought resolves an id to either an R or a T node.
// We check R first because R.thought_ids fans out another level; a T
// id would hit the R miss branch and fall through to T.
func walkReflectionOrThought(cache *store.Cache, id string) traceNode {
	if payload := cache.Get("R", id); payload != nil {
		return walkReflection(cache, id, payload)
	}
	if payload := cache.Get("T", id); payload != nil {
		return walkThought(id, payload)
	}
	return traceNode{Layer: "?", ID: id, Summary: "[missing]", Error: "missing", Children: []traceNode{}}
}

func walkReflection(cache *store.Cache, id string, payload []byte) traceNode {
	var refl map[string]interface{}
	if err := json.Unmarshal(payload, &refl); err != nil {
		return traceNode{Layer: "R", ID: id, Summary: "[malformed]", Error: "malformed", Children: []traceNode{}}
	}
	n := traceNode{
		Layer:    "R",
		ID:       id,
		Summary:  summariseReflection(refl),
		Children: []traceNode{},
	}
	seen := map[string]bool{}
	for _, tid := range stringSlice(refl["thought_ids"]) {
		if seen[tid] {
			continue
		}
		seen[tid] = true
		if tp := cache.Get("T", tid); tp != nil {
			n.Children = append(n.Children, walkThought(tid, tp))
		} else {
			n.Children = append(n.Children, traceNode{
				Layer: "T", ID: tid, Summary: "[missing]", Error: "missing", Children: []traceNode{},
			})
		}
	}
	return n
}

func walkThought(id string, payload []byte) traceNode {
	var th map[string]interface{}
	if err := json.Unmarshal(payload, &th); err != nil {
		return traceNode{Layer: "T", ID: id, Summary: "[malformed]", Error: "malformed", Children: []traceNode{}}
	}
	return traceNode{
		Layer:    "T",
		ID:       id,
		Summary:  summariseThought(th),
		Children: []traceNode{},
	}
}

// ----- summary helpers -----

// summariseArtifact picks content.title when present; else format.
func summariseArtifact(art map[string]interface{}) string {
	if c, ok := art["content"].(map[string]interface{}); ok {
		if t, ok := c["title"].(string); ok && t != "" {
			return truncate(t, summaryMaxLen)
		}
	}
	if f, ok := art["format"].(string); ok {
		return f
	}
	return ""
}

// summariseReflection: strategy + short content hint.
func summariseReflection(refl map[string]interface{}) string {
	strat, _ := refl["strategy"].(string)
	hint := mapFirstStringValue(refl["content"])
	if strat != "" && hint != "" {
		return strat + ": " + truncate(hint, summaryMaxLen)
	}
	if strat != "" {
		return strat
	}
	return truncate(hint, summaryMaxLen)
}

// summariseInsight: synthesis_mode + short content hint.
func summariseInsight(ins map[string]interface{}) string {
	mode, _ := ins["synthesis_mode"].(string)
	hint := mapFirstStringValue(ins["content"])
	if mode != "" && hint != "" {
		return mode + ": " + truncate(hint, summaryMaxLen)
	}
	if mode != "" {
		return mode
	}
	return truncate(hint, summaryMaxLen)
}

// summariseThought: first 80 chars of content (string form or ref).
func summariseThought(th map[string]interface{}) string {
	switch c := th["content"].(type) {
	case string:
		return truncate(c, summaryMaxLen)
	case map[string]interface{}:
		if r, ok := c["ref"].(string); ok {
			return truncate(r, summaryMaxLen)
		}
	}
	return ""
}

// artifactInsightIDs returns the union of provenance.i_ids and insight_ids.
func artifactInsightIDs(art map[string]interface{}) []string {
	var out []string
	if prov, ok := art["provenance"].(map[string]interface{}); ok {
		out = append(out, stringSlice(prov["i_ids"])...)
	}
	out = append(out, stringSlice(art["insight_ids"])...)
	// De-dup.
	seen := map[string]bool{}
	dedup := out[:0]
	for _, id := range out {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		dedup = append(dedup, id)
	}
	return dedup
}

// stringSlice converts an `interface{}` holding `[]interface{}` (JSON
// array of strings) into `[]string`. Non-string entries are skipped.
func stringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// mapFirstStringValue returns an arbitrary string value from a map
// content (for summaries). Deterministic-ish: picks the lex-smallest
// key name among those with string values, falling back to non-string
// stringification via json.Marshal.
func mapFirstStringValue(v interface{}) string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return ""
	}
	// Sort keys for determinism.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple lex sort.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	// No string value — json-encode the first key.
	if len(keys) > 0 {
		b, _ := json.Marshal(m[keys[0]])
		return string(b)
	}
	return ""
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	// Trim on rune boundary where possible; cheap fallback here is
	// byte-truncation which is safe for UTF-8 if we back off at a
	// continuation byte.
	end := n
	for end > 0 && end < len(s) && (s[end]&0xC0) == 0x80 {
		end--
	}
	return strings.TrimRight(s[:end], " ") + "…"
}
