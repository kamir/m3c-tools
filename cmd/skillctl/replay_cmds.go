// replay_cmds.go — `skillctl invoke-replay` (SPEC-0202 P9).
//
// Read-only operator tool. Pulls invocation events from
//
//	GET <base>/api/skills/runtime/invocations?tenant=<id>&limit=N&since_ts=N
//
// (admin-authed via X-API-KEY) and renders them as a chronological table or
// a JSON array. Useful for forensic replay after an incident, or for
// validating that the Phase-2 audit pipe is recording events correctly.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// printReplayUsage prints the help text for `skillctl invoke-replay`.
func printReplayUsage() {
	fmt.Print(`skillctl invoke-replay — pull invocation events from aims-core

Usage:
  skillctl invoke-replay --tenant <id> [--token-id <id>] [--limit 200]
                         [--since <iso8601>] [--target <prod|stage|local>]
                         [--api-key-from <file>] [--format text|json]

Required:
  --tenant <id>       Tenant scope to query.

Optional:
  --token-id <id>     Filter to a single token_id.
  --limit <n>         Max rows to fetch (default: 200).
  --since <ts>        ISO-8601 lower bound (default: none).
  --target <env>      prod | stage | local (default: local).
  --api-key-from <f>  File containing API key (default: ~/.claude/api-key).
  --format <fmt>      text (default) | json.

Examples:
  skillctl invoke-replay --tenant kup-001 --target stage
  skillctl invoke-replay --tenant kup-001 --token-id ct:01HZ... --format json
`)
}

// replayEvent is a permissive shape that matches both the in-process
// skillgate.InvocationEvent and the wrapper-level run events posted by
// `skillctl run`.
type replayEvent struct {
	Type         string `json:"type"`
	TokenID      string `json:"token_id"`
	SkillName    string `json:"skill_name"`
	Tenant       string `json:"tenant"`
	Timestamp    string `json:"timestamp"`
	RefusalCode  string `json:"refusal_code,omitempty"`
	RequestedCmd string `json:"requested_cmd,omitempty"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	DurationMS   *int64 `json:"duration_ms,omitempty"`
}

// replayResponse is the wire shape returned by the GET endpoint. We accept
// either a top-level array OR a {events: [...]} envelope to be tolerant of
// either back-end shape.
type replayResponse struct {
	Events []replayEvent `json:"events"`
}

// runReplay is the entrypoint for `skillctl invoke-replay`.
func runReplay(args []string) int {
	tenant := ""
	tokenID := ""
	limit := 200
	since := ""
	target := "local"
	apiKeyFrom := ""
	format := "text"

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--tenant":
			if i+1 < len(args) {
				i++
				tenant = args[i]
			}
		case "--token-id":
			if i+1 < len(args) {
				i++
				tokenID = args[i]
			}
		case "--limit":
			if i+1 < len(args) {
				i++
				if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
					limit = n
				}
			}
		case "--since":
			if i+1 < len(args) {
				i++
				since = args[i]
			}
		case "--target":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case "--api-key-from":
			if i+1 < len(args) {
				i++
				apiKeyFrom = args[i]
			}
		case "--format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "-h", "--help":
			printReplayUsage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "skillctl invoke-replay: unknown flag: %s\n", a)
			printReplayUsage()
			return 2
		}
	}

	if tenant == "" {
		fmt.Fprintln(os.Stderr, "skillctl invoke-replay: --tenant is required")
		return 2
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(os.Stderr, "skillctl invoke-replay: invalid --format %q (text|json)\n", format)
		return 2
	}

	apiKey, err := resolveReplayAPIKey(apiKeyFrom)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl invoke-replay: %v\n", err)
		return 2
	}

	base := defaultReplayBaseURL(target)
	q := url.Values{}
	q.Set("tenant", tenant)
	q.Set("limit", strconv.Itoa(limit))
	if since != "" {
		// Accept ISO-8601; convert to unix seconds.
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			q.Set("since_ts", strconv.FormatInt(t.Unix(), 10))
		} else if t2, err := time.Parse("2006-01-02T15:04:05Z", since); err == nil {
			q.Set("since_ts", strconv.FormatInt(t2.Unix(), 10))
		} else {
			// Treat as raw unix seconds if it parses as int.
			q.Set("since_ts", since)
		}
	}
	endpoint := strings.TrimRight(base, "/") + "/api/skills/runtime/invocations?" + q.Encode()

	events, err := fetchReplayEvents(endpoint, apiKey, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl invoke-replay: %v\n", err)
		return 1
	}

	// Filter by token_id if requested.
	if tokenID != "" {
		filtered := make([]replayEvent, 0, len(events))
		for _, e := range events {
			if e.TokenID == tokenID {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	// Sort chronologically (timestamp ascending).
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(events); err != nil {
			fmt.Fprintf(os.Stderr, "skillctl invoke-replay: encode: %v\n", err)
			return 1
		}
		return 0
	}

	renderReplayTable(os.Stdout, events, isStdoutTTY())
	return 0
}

// fetchReplayEvents performs the GET and unmarshals into a slice of events.
// Tolerant: accepts either top-level array OR {events: [...]}.
func fetchReplayEvents(endpoint, apiKey, target string) ([]replayEvent, error) {
	client := newReplayHTTPClient(target)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}
	req.Header.Set("Accept", "application/json")

	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Try array form first.
	var arr []replayEvent
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}
	// Fall back to envelope form.
	var env replayResponse
	if err := json.Unmarshal(body, &env); err == nil {
		return env.Events, nil
	}
	return nil, fmt.Errorf("unparseable response (first 200 bytes): %s", truncBytes(body, 200))
}

// renderReplayTable prints a chronological table to w. ANSI colors are used
// only when colorize=true.
func renderReplayTable(w io.Writer, events []replayEvent, colorize bool) {
	if len(events) == 0 {
		fmt.Fprintln(w, "(no events)")
		return
	}

	// Header.
	fmt.Fprintf(w, "%-22s  %-18s  %-24s  %-14s  %s\n",
		"TIMESTAMP", "TYPE", "SKILL", "TOKEN_ID", "CODE/EXIT")
	fmt.Fprintln(w, strings.Repeat("-", 100))

	typeCounts := map[string]int{}
	var first, last string
	for i, e := range events {
		if i == 0 {
			first = e.Timestamp
		}
		last = e.Timestamp
		typeCounts[e.Type]++

		typeStr := e.Type
		if colorize {
			typeStr = colorForType(e.Type) + typeStr + ansiReset
		}

		codeOrExit := ""
		switch {
		case e.RefusalCode != "":
			codeOrExit = e.RefusalCode
		case e.ExitCode != nil:
			codeOrExit = fmt.Sprintf("exit=%d", *e.ExitCode)
			if e.DurationMS != nil {
				codeOrExit += fmt.Sprintf(" (%dms)", *e.DurationMS)
			}
		}

		tokTrunc := truncString(e.TokenID, 14)
		skillTrunc := truncString(e.SkillName, 24)
		// Use Sprintf for width on the colorized type column to keep
		// column alignment correct (ANSI codes are zero-width).
		typeCol := padRight(e.Type, 18)
		if colorize {
			typeCol = colorForType(e.Type) + padRight(e.Type, 18) + ansiReset
		}
		fmt.Fprintf(w, "%-22s  %s  %-24s  %-14s  %s\n",
			truncString(e.Timestamp, 22), typeCol, skillTrunc, tokTrunc, codeOrExit)
		_ = typeStr // keep variable used for clarity
	}

	// Footer.
	fmt.Fprintln(w, strings.Repeat("-", 100))
	fmt.Fprintf(w, "Total: %d events  |  first: %s  |  last: %s\n", len(events), first, last)

	// Per-type breakdown — stable order.
	keys := make([]string, 0, len(typeCounts))
	for k := range typeCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		label := k
		if colorize {
			label = colorForType(k) + k + ansiReset
		}
		parts = append(parts, fmt.Sprintf("%s=%d", label, typeCounts[k]))
	}
	fmt.Fprintf(w, "By type: %s\n", strings.Join(parts, "  "))
}

// ANSI color constants. A small palette per the task spec.
const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiCyan   = "\x1b[36m"
	ansiGold   = "\x1b[33m"
	ansiPurple = "\x1b[35m"
)

func colorForType(t string) string {
	switch t {
	case "gate.allowed":
		return ansiGreen
	case "gate.refused":
		return ansiRed
	case "skill.invoked":
		return ansiCyan
	case "skill.completed":
		return ansiGold
	default:
		return ansiPurple
	}
}

// replay_cmds previously defined isStdoutTTY; audit_cmds.go owns it now.
// The two implementations were identical (stdlib-only, fi.Mode() & ModeCharDevice).
// Removed to fix the package-level "redeclared in this block" build error.

// resolveReplayAPIKey reads the API key. Unlike the run wrapper, replay
// REQUIRES the key (the endpoint is admin-only); missing → error.
func resolveReplayAPIKey(explicit string) (string, error) {
	path := explicit
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".claude", "api-key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("api key file %s: %w", path, err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("api key file %s is empty", path)
	}
	return key, nil
}

// defaultReplayBaseURL maps --target → base URL (no /api/... suffix).
func defaultReplayBaseURL(target string) string {
	switch target {
	case "prod":
		return "https://onboarding.guide"
	case "stage":
		base := readDeployEnvStageURL()
		if base == "" {
			base = "https://youtube-summarizer-mvp-v1-bf2osjjeqa-lz.a.run.app"
		}
		return base
	default:
		return "https://127.0.0.1:8081"
	}
}

func newReplayHTTPClient(target string) *http.Client {
	if target == "local" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// truncString returns s[:n] + "…" if len(s) > n, else s.
func truncString(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// padRight pads s with spaces to width n.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// truncBytes returns the first n bytes of b as a string (with "..." if cut).
func truncBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
