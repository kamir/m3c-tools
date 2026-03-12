package timetracking

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ReverseTracker creates inferred time blocks from observation uploads by
// matching observation tags against PLM project tags (REQ-9).
type ReverseTracker struct {
	store      *Store
	mu         sync.Mutex
	enabled    bool
	blockDur   time.Duration
	minOverlap int
}

// NewReverseTracker creates a ReverseTracker reading config from env vars.
func NewReverseTracker(store *Store) *ReverseTracker {
	enabled := true
	if v := os.Getenv("M3C_REVERSE_BLOCK_ENABLED"); strings.EqualFold(v, "false") {
		enabled = false
	}
	blockDur := 900 * time.Second
	if v := os.Getenv("M3C_REVERSE_BLOCK_DURATION"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			blockDur = time.Duration(secs) * time.Second
		}
	}
	minOverlap := 2
	if v := os.Getenv("M3C_REVERSE_MIN_TAG_OVERLAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			minOverlap = n
		}
	}
	return &ReverseTracker{
		store:      store,
		enabled:    enabled,
		blockDur:   blockDur,
		minOverlap: minOverlap,
	}
}

// matchResult holds the result of tag matching against a project.
type matchResult struct {
	ProjectID   string
	ProjectName string
	Score       int
	MatchType   string
	UpdatedAt   time.Time
}

// ProcessObservation checks if the given observation's tags match a project
// and creates an inferred time block if appropriate.
func (rt *ReverseTracker) ProcessObservation(obsTime time.Time, tagStr string, docID string) error {
	if !rt.enabled {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	obsTags := splitTags(tagStr)
	if len(obsTags) == 0 {
		return nil
	}

	projects, err := rt.store.ListProjects()
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}
	if len(projects) == 0 {
		return nil
	}

	match := rt.bestMatch(obsTags, projects)
	if match == nil {
		log.Printf("[reverse-tracking] no project match for tags=%q", tagStr)
		return nil
	}

	halfBlock := rt.blockDur / 2
	blockStart := obsTime.Add(-halfBlock).UTC()
	blockEnd := obsTime.Add(halfBlock).UTC()

	// Check for existing explicit or inferred sessions covering this timestamp.
	checkFrom := blockStart.Add(-time.Hour)
	checkTo := blockEnd.Add(time.Hour)
	events, err := rt.store.ListEvents(match.ProjectID, checkFrom, checkTo)
	if err != nil {
		return fmt.Errorf("check events: %w", err)
	}

	if hasExplicitCoverage(events, obsTime.UTC()) {
		log.Printf("[reverse-tracking] explicit session covers t=%s project=%s — skip",
			obsTime.Format(time.RFC3339), match.ProjectID)
		return nil
	}

	if hasInferredNearby(events, obsTime.UTC(), halfBlock) {
		log.Printf("[reverse-tracking] inferred block nearby t=%s project=%s — skip",
			obsTime.Format(time.RFC3339), match.ProjectID)
		return nil
	}

	// Create activate + deactivate event pair.
	durSec := int(blockEnd.Sub(blockStart).Seconds())

	if err := rt.store.InsertEvent(Event{
		EventID:     uuid.New().String(),
		ProjectID:   match.ProjectID,
		ProjectName: match.ProjectName,
		EventType:   "activate",
		Timestamp:   blockStart,
		Trigger:     "observation_inferred",
		ContentRef:  docID,
	}); err != nil {
		return fmt.Errorf("insert activate: %w", err)
	}

	if err := rt.store.InsertEvent(Event{
		EventID:     uuid.New().String(),
		ProjectID:   match.ProjectID,
		ProjectName: match.ProjectName,
		EventType:   "deactivate",
		Timestamp:   blockEnd,
		Trigger:     "observation_inferred",
		DurationSec: &durSec,
		ContentRef:  docID,
	}); err != nil {
		return fmt.Errorf("insert deactivate: %w", err)
	}

	log.Printf("[reverse-tracking] created %ds block project=%s name=%q match=%s(%d) doc=%s",
		durSec, match.ProjectID, match.ProjectName, match.MatchType, match.Score, docID)
	return nil
}

// RecordAndProcess records an observation for future replay, then runs
// ProcessObservation immediately. This is the primary entry point for
// upload hooks (REQ-10).
func (rt *ReverseTracker) RecordAndProcess(obsTime time.Time, tagStr, docID, obsType string) error {
	// Always record, even if reverse tracking is disabled — enables future backfill.
	obs := Observation{
		ObsID:     uuid.New().String(),
		Timestamp: obsTime,
		Tags:      tagStr,
		DocID:     docID,
		ObsType:   obsType,
	}
	if err := rt.store.RecordObservation(obs); err != nil {
		log.Printf("[reverse-tracking] record observation failed: %v", err)
	}

	return rt.ProcessObservation(obsTime, tagStr, docID)
}

// BackfillPeriod replays all recorded observations in the given time range
// through ProcessObservation. Dedup is handled by ProcessObservation itself.
func (rt *ReverseTracker) BackfillPeriod(from, to time.Time) (int, error) {
	if !rt.enabled {
		return 0, nil
	}

	observations, err := rt.store.ListObservations(from, to)
	if err != nil {
		return 0, fmt.Errorf("list observations: %w", err)
	}
	if len(observations) == 0 {
		return 0, nil
	}

	processed := 0
	for _, obs := range observations {
		if err := rt.ProcessObservation(obs.Timestamp, obs.Tags, obs.DocID); err != nil {
			log.Printf("[reverse-tracking] backfill skip obs=%s: %v", obs.ObsID, err)
			continue
		}
		processed++
	}
	log.Printf("[reverse-tracking] backfill %s–%s: %d/%d observations processed",
		from.Format("2006-01-02"), to.Format("2006-01-02"), processed, len(observations))
	return processed, nil
}

// bestMatch finds the project with the highest tag match score.
func (rt *ReverseTracker) bestMatch(obsTags []string, projects []CachedProject) *matchResult {
	// Parse observation tags into key-value and plain sets.
	obsKV := make(map[string]string)
	obsPlain := make(map[string]bool)

	for _, t := range obsTags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		lower := strings.ToLower(t)
		if idx := strings.Index(lower, ":"); idx > 0 {
			obsKV[lower[:idx]] = lower[idx+1:]
		} else {
			obsPlain[lower] = true
		}
	}

	// Skip if only generic type tags with no structured metadata.
	genericOnly := true
	for tag := range obsPlain {
		switch tag {
		case "youtube", "idea", "impulse", "audio-import":
			// generic type tag
		default:
			genericOnly = false
		}
	}
	if genericOnly && len(obsKV) == 0 {
		return nil
	}

	var best *matchResult

	for _, p := range projects {
		projTags := splitTags(p.Tags)
		projTagSet := make(map[string]bool)
		projKV := make(map[string]string)

		for _, t := range projTags {
			lower := strings.ToLower(strings.TrimSpace(t))
			if lower == "" {
				continue
			}
			if idx := strings.Index(lower, ":"); idx > 0 {
				projKV[lower[:idx]] = lower[idx+1:]
			}
			projTagSet[lower] = true
		}

		score := 0
		matchType := ""

		// Strong match: observation has project:{name} matching project name or tags.
		if projVal, ok := obsKV["project"]; ok {
			if strings.EqualFold(projVal, p.Name) ||
				projTagSet[projVal] ||
				projTagSet["project:"+projVal] {
				score = 100
				matchType = "project"
			}
		}

		// Medium match: observation has client:{name} matching project's client or tags.
		if score < 50 {
			if clientVal, ok := obsKV["client"]; ok {
				if strings.EqualFold(clientVal, p.Client) ||
					projTagSet[clientVal] ||
					projTagSet["client:"+clientVal] {
					score = 50
					matchType = "client"
				}
			}
		}

		// Weak match: plain tag overlap (≥ minOverlap).
		if score < 20 {
			overlap := 0
			for tag := range obsPlain {
				switch tag {
				case "youtube", "idea", "impulse", "audio-import":
					continue // skip generic type tags
				}
				if projTagSet[tag] {
					overlap++
				}
			}
			// Also count matching key-value pairs (topic:xxx matches topic:xxx).
			for key, val := range obsKV {
				if key == "project" || key == "client" || key == "video_id" || key == "source" {
					continue
				}
				if pval, ok := projKV[key]; ok && pval == val {
					overlap++
				}
			}
			if overlap >= rt.minOverlap {
				score = 10 * overlap
				matchType = "tag_overlap"
			}
		}

		if score <= 0 {
			continue
		}

		if best == nil || score > best.Score ||
			(score == best.Score && p.UpdatedAt.After(best.UpdatedAt)) {
			best = &matchResult{
				ProjectID:   p.ProjectID,
				ProjectName: p.Name,
				Score:       score,
				MatchType:   matchType,
				UpdatedAt:   p.UpdatedAt,
			}
		}
	}

	return best
}

// hasExplicitCoverage returns true if a non-inferred session covers the given time.
func hasExplicitCoverage(events []Event, t time.Time) bool {
	var lastActivate *time.Time

	for _, e := range events {
		if e.Trigger == "observation_inferred" {
			continue
		}
		switch e.EventType {
		case "activate":
			ts := e.Timestamp
			lastActivate = &ts
		case "deactivate":
			if lastActivate != nil && !t.Before(*lastActivate) && !t.After(e.Timestamp) {
				return true
			}
			lastActivate = nil
		}
	}

	// Open activation (no deactivate) covering t.
	if lastActivate != nil && !t.Before(*lastActivate) {
		return true
	}
	return false
}

// hasInferredNearby returns true if an inferred event already exists within
// halfBlock of the observation time.
func hasInferredNearby(events []Event, t time.Time, halfBlock time.Duration) bool {
	for _, e := range events {
		if e.Trigger != "observation_inferred" {
			continue
		}
		gap := e.Timestamp.Sub(t)
		if gap < 0 {
			gap = -gap
		}
		if gap <= halfBlock {
			return true
		}
	}
	return false
}

// splitTags splits a comma-separated tag string into individual tags.
func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
