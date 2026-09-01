package main

// gate_stats_cmds.go — SPEC-0255: `skillctl gate-stats` summarises the
// append-only gate-audit.jsonl that the hook + sweep write. Read-only; the log
// is advisory telemetry, never a trust input. Malformed/tampered lines are
// skipped, not fatal.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type skillCount struct {
	Skill string `json:"skill"`
	Count int    `json:"count"`
}

type reasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type gateStatsSummary struct {
	Total         int            `json:"total"`
	Since         string         `json:"since,omitempty"`
	ByDecision    map[string]int `json:"by_decision"`
	BySource      map[string]int `json:"by_source"`
	HookCount     int            `json:"hook_count"`
	HookCacheRate float64        `json:"hook_cache_hit_rate"`
	TopDenied     []skillCount   `json:"top_denied_skills"`
	TopDenyReason []reasonCount  `json:"top_deny_reasons"`
	RecentDenials []gateEvent    `json:"recent_denials"`
}

func runGateStats(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gate-stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.String("since", "", "Only events newer than this — a Go duration (e.g. 168h) or a date (YYYY-MM-DD).")
	jsonOut := fs.Bool("json", false, "Emit the summary as stable JSON.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := userHome()
	if err != nil || home == "" {
		fmt.Fprintln(stderr, "gate-stats: cannot resolve home dir")
		return exitGeneric
	}
	cutoff, err := parseGateSince(*since, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "gate-stats: bad --since %q: %v\n", *since, err)
		return 2
	}

	sum := aggregateGateAudit(home, cutoff)
	if *since != "" {
		sum.Since = *since
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sum) // map keys sort + slices pre-sorted → stable output
		return exitOK
	}
	printGateStatsHuman(stdout, sum)
	return exitOK
}

// parseGateSince accepts a Go duration ("168h") or a date ("2006-01-02"); ""
// means no time filter (zero time).
func parseGateSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("not a duration (e.g. 168h) or a date (YYYY-MM-DD)")
}

func aggregateGateAudit(home string, cutoff time.Time) gateStatsSummary {
	sum := gateStatsSummary{ByDecision: map[string]int{}, BySource: map[string]int{}}
	deniedSkills := map[string]int{}
	denyReasons := map[string]int{}
	hookHits := 0
	var recent []gateEvent

	scanFile := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			return // missing generation is fine
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // tolerate long lines; over-long → skipped
		for sc.Scan() {
			var ev gateEvent
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				continue // malformed / tampered line → skip, never fatal
			}
			if !cutoff.IsZero() {
				t, err := time.Parse(time.RFC3339, ev.Ts)
				if err != nil || t.Before(cutoff) {
					continue
				}
			}
			sum.Total++
			sum.ByDecision[ev.Decision]++
			sum.BySource[ev.Source]++
			if ev.Source == "hook" {
				sum.HookCount++
				if ev.CacheHit {
					hookHits++
				}
			}
			if ev.Decision == "deny" || ev.Decision == "quarantine" {
				deniedSkills[ev.Skill]++
				if ev.Reason != "" {
					denyReasons[ev.Reason]++
				}
				recent = append(recent, ev)
			}
		}
	}
	// Older rotated generation first, then the live file, so recent[] trends newest-last.
	scanFile(gateAuditPath(home) + ".1")
	scanFile(gateAuditPath(home))

	sum.TopDenied = topSkills(deniedSkills, 10)
	sum.TopDenyReason = topReasons(denyReasons, 10)
	if sum.HookCount > 0 {
		sum.HookCacheRate = float64(hookHits) / float64(sum.HookCount)
	}
	const lastN = 10
	if len(recent) > lastN {
		recent = recent[len(recent)-lastN:]
	}
	sum.RecentDenials = recent
	return sum
}

func topSkills(m map[string]int, n int) []skillCount {
	out := make([]skillCount, 0, len(m))
	for k, v := range m {
		out = append(out, skillCount{Skill: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Skill < out[j].Skill // tie-break for stable output
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topReasons(m map[string]int, n int) []reasonCount {
	out := make([]reasonCount, 0, len(m))
	for k, v := range m {
		out = append(out, reasonCount{Reason: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func printGateStatsHuman(w io.Writer, s gateStatsSummary) {
	fmt.Fprintf(w, "gate-audit summary — %d event(s)", s.Total)
	if s.Since != "" {
		fmt.Fprintf(w, " since %s", s.Since)
	}
	fmt.Fprintln(w)
	if s.Total == 0 {
		fmt.Fprintln(w, "  (no events — the gate hasn't logged anything in this window)")
		return
	}
	fmt.Fprintf(w, "  decisions: ")
	for _, d := range []string{"allow", "deny", "quarantine", "leave"} {
		if c := s.ByDecision[d]; c > 0 {
			fmt.Fprintf(w, "%s=%d  ", d, c)
		}
	}
	fmt.Fprintf(w, "\n  sources:   hook=%d sweep=%d\n", s.BySource["hook"], s.BySource["sweep"])
	if s.HookCount > 0 {
		fmt.Fprintf(w, "  hook cache-hit rate: %.0f%% (%d hook events)\n", s.HookCacheRate*100, s.HookCount)
	}
	if len(s.TopDenied) > 0 {
		fmt.Fprintln(w, "  top blocked skills:")
		for _, sc := range s.TopDenied {
			fmt.Fprintf(w, "    %3d  %s\n", sc.Count, sc.Skill)
		}
	}
	if len(s.RecentDenials) > 0 {
		fmt.Fprintln(w, "  recent blocks:")
		for _, e := range s.RecentDenials {
			fmt.Fprintf(w, "    %s  %-10s %s — %s (exit %d)\n", e.Ts, e.Decision, e.Skill, e.Reason, e.ExitCode)
		}
	}
}
