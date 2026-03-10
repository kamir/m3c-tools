package impression

import (
	"regexp"
	"strings"
)

// MetadataTags holds structured metadata extracted from a filename.
// It separates plain tags from key-value metadata, hash tags, and
// categories, enabling richer tag integration with the ER1 upload pipeline.
type MetadataTags struct {
	// Plain are simple word tags (e.g. "braindump", "meeting").
	Plain []string
	// KeyValue are structured metadata pairs (e.g. "speaker:john").
	KeyValue map[string]string
	// HashTags are tags prefixed with # in the filename (stored without #).
	HashTags []string
	// Categories are bracket-enclosed labels (e.g. "[draft]" → "draft").
	Categories []string
	// Source is the detected recording device or application (e.g. "zoom", "dictaphone").
	Source string
}

// knownKeyPrefixes are recognised metadata key prefixes. When a filename
// contains a token like "speaker-john" or "project-alpha", it is parsed
// as a key-value pair rather than two separate tags.
var knownKeyPrefixes = map[string]bool{
	"speaker":  true,
	"project":  true,
	"topic":    true,
	"channel":  true,
	"lang":     true,
	"language": true,
	"client":   true,
	"session":  true,
	"source":   true,
	"type":     true,
	"context":  true,
	"location": true,
	"event":    true,
}

// devicePatterns maps known device/app prefixes to a normalised source name.
// These are matched case-insensitively against the first token of a filename.
var devicePatterns = map[string]string{
	"zoom":   "zoom",
	"dm":     "dictaphone",
	"dic":    "dictaphone",
	"voice":  "voice-memo",
	"vm":     "voice-memo",
	"rec":    "recorder",
	"record": "recorder",
	"otter":  "otter",
	"rev":    "rev",
}

// Regex patterns for metadata extraction.
// These match against the raw base name (before separator splitting).
// Values are restricted to alphanumeric characters only (no underscores
// or hyphens) because those characters serve as filename separators.
var (
	// hashTagRe matches #tag tokens (alphanumeric only after #).
	hashTagRe = regexp.MustCompile(`#([A-Za-z][A-Za-z0-9]*)`)
	// bracketRe matches [category] tokens (alphanumeric plus hyphen inside brackets).
	bracketRe = regexp.MustCompile(`\[([A-Za-z][A-Za-z0-9-]*)\]`)
	// kvColonRe matches key:value tokens (alphanumeric only on both sides).
	kvColonRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*):([A-Za-z][A-Za-z0-9]*)`)
)

// ParseMetadataTags extracts structured metadata from a filename.
// It builds on ParseFilename and additionally parses:
//   - Key-value pairs: "speaker-john" (with known prefix) or "key:value"
//   - Hash tags: "#meeting"
//   - Bracket categories: "[draft]"
//   - Device/source detection: "ZOOM0001" → source "zoom"
//
// The returned MetadataTags.Plain contains only tags that are NOT
// captured as key-value, hash, or category entries.
func ParseMetadataTags(filename string) MetadataTags {
	info := ParseFilename(filename)
	return ExtractMetadata(info.BaseName, info.Tags)
}

// ExtractMetadata parses structured metadata from a base filename and
// its pre-extracted plain tags. This is useful when you already have a
// FilenameInfo from ParseFilename and want to layer metadata extraction
// on top.
func ExtractMetadata(baseName string, plainTags []string) MetadataTags {
	mt := MetadataTags{
		KeyValue: make(map[string]string),
	}

	// 1. Extract hash tags from the original base name.
	for _, m := range hashTagRe.FindAllStringSubmatch(baseName, -1) {
		mt.HashTags = append(mt.HashTags, strings.ToLower(m[1]))
	}

	// 2. Extract bracket categories from the original base name.
	for _, m := range bracketRe.FindAllStringSubmatch(baseName, -1) {
		mt.Categories = append(mt.Categories, strings.ToLower(m[1]))
	}

	// 3. Extract colon-separated key:value pairs from the original base name.
	for _, m := range kvColonRe.FindAllStringSubmatch(baseName, -1) {
		key := strings.ToLower(m[1])
		val := strings.ToLower(m[2])
		mt.KeyValue[key] = val
	}

	// 4. Detect device/source from the base name (first token).
	mt.Source = detectSource(baseName)

	// 5. Process plain tags: separate known-prefix key-value pairs.
	// Plain tags come from extractTags() which splits on separators and
	// lowercases, but may include tokens like "#meeting", "[draft]", or
	// "speaker:john" which we need to filter out.
	consumed := make(map[string]bool) // track tags consumed as KV values
	for i := 0; i < len(plainTags)-1; i++ {
		key := plainTags[i]
		if knownKeyPrefixes[key] {
			val := plainTags[i+1]
			mt.KeyValue[key] = val
			consumed[key] = true
			consumed[val] = true
			i++ // skip the value token
		}
	}

	// Build sets for filtering.
	hashSet := setFromSlice(mt.HashTags)
	catSet := setFromSlice(mt.Categories)

	for _, tag := range plainTags {
		if consumed[tag] {
			continue
		}
		// Skip tags that are hash tags (with or without # prefix).
		clean := strings.TrimPrefix(tag, "#")
		if hashSet[clean] {
			continue
		}
		// Skip tags that are categories (with or without brackets).
		stripped := strings.TrimPrefix(strings.TrimSuffix(tag, "]"), "[")
		if catSet[stripped] {
			continue
		}
		// Skip tags that contain a colon (already captured as KV).
		if strings.Contains(tag, ":") {
			continue
		}
		mt.Plain = append(mt.Plain, tag)
	}

	// If source was detected from a device prefix, remove device tokens
	// from plain tags to avoid duplication.
	if mt.Source != "" {
		mt.Plain = filterOut(mt.Plain, mt.Source)
		for prefix, src := range devicePatterns {
			if src == mt.Source {
				mt.Plain = filterOut(mt.Plain, prefix)
			}
		}
	}

	return mt
}

// AllTags returns all metadata as a flat tag slice suitable for ER1 upload.
// Key-value pairs are formatted as "key:value". Hash tags, categories,
// and the source are included alongside plain tags.
func (mt MetadataTags) AllTags() []string {
	var tags []string

	// Plain tags first.
	tags = append(tags, mt.Plain...)

	// Key-value pairs (sorted for deterministic output).
	kvKeys := make([]string, 0, len(mt.KeyValue))
	for k := range mt.KeyValue {
		kvKeys = append(kvKeys, k)
	}
	sortStrings(kvKeys)
	for _, k := range kvKeys {
		tags = append(tags, k+":"+mt.KeyValue[k])
	}

	// Hash tags (without # prefix).
	tags = append(tags, mt.HashTags...)

	// Categories.
	for _, c := range mt.Categories {
		tags = append(tags, "category:"+c)
	}

	// Source.
	if mt.Source != "" {
		tags = append(tags, "source:"+mt.Source)
	}

	return tags
}

// MergedTagString returns all metadata tags as a comma-separated string,
// suitable for direct use with BuildImportTags or ER1 upload payloads.
func (mt MetadataTags) MergedTagString() string {
	return strings.Join(mt.AllTags(), ",")
}

// HasKeyValue reports whether the metadata contains the given key.
func (mt MetadataTags) HasKeyValue(key string) bool {
	_, ok := mt.KeyValue[strings.ToLower(key)]
	return ok
}

// Get returns the value for a metadata key, or empty string if not present.
func (mt MetadataTags) Get(key string) string {
	return mt.KeyValue[strings.ToLower(key)]
}

// detectSource checks the base filename for known device/app prefixes.
func detectSource(baseName string) string {
	// Normalise: replace separators, lowercase, take first token.
	r := strings.NewReplacer("_", " ", "-", " ", ".", " ")
	tokens := strings.Fields(r.Replace(strings.ToLower(baseName)))
	if len(tokens) == 0 {
		return ""
	}

	first := tokens[0]

	// Strip leading bracket/hash markers.
	first = strings.TrimLeft(first, "#[")

	// Exact match on first token.
	if src, ok := devicePatterns[first]; ok {
		return src
	}

	// Prefix match (e.g. "zoom0001" starts with "zoom").
	for prefix, src := range devicePatterns {
		if strings.HasPrefix(first, prefix) && len(first) > len(prefix) {
			return src
		}
	}

	return ""
}

// setFromSlice creates a set from a string slice.
func setFromSlice(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// filterOut removes all occurrences of val from the slice.
func filterOut(ss []string, val string) []string {
	var result []string
	for _, s := range ss {
		if s != val {
			result = append(result, s)
		}
	}
	return result
}

// sortStrings sorts a string slice in place (simple insertion sort to
// avoid importing sort package for small slices).
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
