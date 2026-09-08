package main

// `skillctl runbook publish`, SPEC-0272: push a generated onboarding runbook
// into the THOH catalog (POST <base>/api/thoh/runbooks).
//
// Why this exists (vs. the tools/skillctl-runbook-publish.sh curl bridge): the
// device token comes from skillctl's OWN keychain item via the FR-0043 autoload
// (autoloadDeviceToken set ER1_DEVICE_TOKEN before we ran), no `security` CLI
// prompt, no token echoed into shell history. Plus a --dry-run plan and a
// governed confirm pause before the prod write. The descriptor matches the
// bridge's (rb-skillctl-publisher) so either path yields the same catalog entry.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func runRunbook(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "publish" {
		fmt.Fprintln(stderr, "Usage: skillctl runbook publish <runbook.html> --tag <tag> [--meta <runbook.meta.json>] [flags]")
		fmt.Fprintln(stderr, "  Publishes an onboarding runbook into the THOH catalog (SPEC-0272).")
		return 2
	}

	fs := flag.NewFlagSet("runbook publish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tag := fs.String("tag", "", "Release tag the runbook belongs to (e.g. skillctl/v0.2.11-rc3). Version = last path segment. Required.")
	base := fs.String("base", envOr("ER1_API_BASE", "https://onboarding.guide"), "THOH catalog base URL.")
	rbID := fs.String("id", "rb-skillctl-publisher", "Runbook id in the catalog.")
	title := fs.String("title", "skillctl: sign & publish a skill", "Catalog title.")
	purpose := fs.String("purpose", "Turn a person into a verified skill publisher", "One-line purpose.")
	goal := fs.String("goal", "A signed, green-attested skill published to the room", "Completion goal.")
	meta := fs.String("meta", "", "Path to a runbook.meta.json sidecar to use as the descriptor, steps[] included (SPEC-0275 G3). Default: the built-in publisher descriptor, which has no steps.")
	dryRun := fs.Bool("dry-run", false, "Print the plan + descriptor; do not POST.")
	yes := fs.Bool("yes", false, "Skip the 🟡 confirm pause (scripted runs).")
	// stdlib flag.Parse stops at the first positional, dropping flags after it;
	// reorder flag-tokens first (same fix as publish_cmds.go).
	if err := fs.Parse(reorderFlagArgs(fs, args[1:])); err != nil {
		return 2
	}
	htmlPath := fs.Arg(0)
	if htmlPath == "" {
		fmt.Fprintln(stderr, "runbook publish: path to the generated runbook HTML required (positional arg 1)")
		return 2
	}
	if strings.TrimSpace(*tag) == "" {
		fmt.Fprintln(stderr, "runbook publish: --tag <release-tag> required (version is its last path segment)")
		return 2
	}
	version := (*tag)[strings.LastIndex(*tag, "/")+1:]

	html, err := os.ReadFile(htmlPath)
	if err != nil {
		fmt.Fprintf(stderr, "runbook publish: read %s: %v\n", htmlPath, err)
		return 1
	}

	endpoint := strings.TrimRight(*base, "/") + "/api/thoh/runbooks"

	// The descriptor. With --meta it is the sidecar (SPEC-0275 G3: one descriptor
	// path, no second hardcoded copy); without it, the built-in publisher descriptor
	// this command has always carried. The built-in one has no steps, which is
	// exactly the BUG-0224 case, so it goes through the same warning check.
	var (
		descriptor map[string]any
		warns      []string
		srcPath    = "tools/release-templates/skillctl-publisher-runbook.template.html"
	)
	if metaPath := strings.TrimSpace(*meta); metaPath != "" {
		d, w, err := loadRunbookDescriptor(metaPath, version)
		if err != nil {
			fmt.Fprintf(stderr, "runbook publish: %v\n", err)
			return 1
		}
		descriptor, warns, srcPath = d, w, metaPath
	} else {
		descriptor = map[string]any{
			"runbook_id":       *rbID,
			"version":          version,
			"title":            *title,
			"purpose":          *purpose,
			"goal":             *goal,
			"tags":             []string{"skillctl", "onboarding", "publisher", "trust"},
			"audience_roles":   []string{"user", "learner", "coach"},
			"governance_level": "green",
		}
		warns = runbookDescriptorWarnings(descriptor)
	}
	// Stamped at publish time, never hand-authored (SPEC-0275 section 4).
	descriptor["source"] = map[string]string{
		"repo":    "m3c-tools",
		"path":    srcPath,
		"release": *tag,
	}
	descriptor["html_url"] = fmt.Sprintf("https://github.com/kamir/m3c-tools/releases/download/%s/skillctl-publisher-runbook.html", *tag)

	rbIDOut, _ := descriptor["runbook_id"].(string)
	titleOut, _ := descriptor["title"].(string)
	fmt.Fprintf(stdout, "Runbook : %s@%s: %q\n", rbIDOut, version, titleOut)
	fmt.Fprintf(stdout, "HTML    : %s (%d bytes)\n", htmlPath, len(html))
	fmt.Fprintf(stdout, "Catalog : POST %s\n", endpoint)

	// BUG-0224: a descriptor without steps used to pass through in silence. It still
	// publishes (a catalog entry is legal), it is no longer quiet about what it is.
	for _, w := range warns {
		fmt.Fprintf(stderr, "runbook publish: warning: %s\n", w)
	}

	if *dryRun {
		pretty, _ := json.MarshalIndent(descriptor, "", "  ")
		fmt.Fprintf(stdout, "\n--dry-run: descriptor that would be posted:\n%s\n", pretty)
		return 0
	}

	token := os.Getenv("ER1_DEVICE_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "runbook publish: no device token: run 'skillctl login' first.")
		return 13
	}

	// 🟡 governed confirm before the prod write.
	if !*yes {
		fmt.Fprintf(stdout, "\n🟡 About to publish into the THOH catalog at %s. Proceed? [y/N] ", *base)
		var resp string
		_, _ = fmt.Fscanln(os.Stdin, &resp)
		if r := strings.ToLower(strings.TrimSpace(resp)); r != "y" && r != "yes" {
			fmt.Fprintln(stdout, "aborted.")
			return 0
		}
	}

	code, out, err := postRunbookToCatalog(*base, token, descriptor, html)
	if err != nil {
		fmt.Fprintf(stderr, "runbook publish: POST failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "HTTP %d %s\n", code, out)

	switch code {
	case 200, 201:
		fmt.Fprintf(stdout, "✓ runbook in catalog, assign it from the THOH board (%s/thoh).\n", strings.TrimRight(*base, "/"))
		return 0
	case 401, 403:
		fmt.Fprintln(stderr, "auth rejected, token invalid/expired (re-run 'skillctl login') or not permitted on this catalog.")
		return 13
	default:
		fmt.Fprintln(stderr, "publish failed.")
		return 1
	}
}

// postRunbookToCatalog POSTs {descriptor, html} to <base>/api/thoh/runbooks with
// the device token. The one wire path shared by `skillctl runbook publish` and the
// SPEC-0275 `skillctl publish` auto-register hook (no descriptor duplication).
func postRunbookToCatalog(base, token string, descriptor map[string]any, html []byte) (int, string, error) {
	endpoint := strings.TrimRight(base, "/") + "/api/thoh/runbooks"
	body, _ := json.Marshal(map[string]any{"descriptor": descriptor, "html": string(html)})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(out)), nil
}

// maybeRegisterRunbook is the SPEC-0275 auto-register hook. After a successful
// `skillctl publish` admit, if the skill dir carries BOTH runbook.html and the
// sidecar runbook.meta.json (and --no-runbook-publish wasn't passed), it posts
// them to the THOH catalog. Best-effort: every failure warns but NEVER fails the
// publish. The admit is already done and the runbook bytes are in the signed
// .skb regardless. The descriptor is the sidecar; version is overridden by the
// authoritative skill version (single source of truth).
//
//	publish admit OK ──▶ runbook.html + runbook.meta.json present?
//	                       ├─ neither      → silent (skill ships no runbook)
//	                       ├─ only one     → WARN, skip
//	                       └─ both         → validate(runbook_id,title) → POST (best-effort)
func maybeRegisterRunbook(stdout, stderr io.Writer, a publishAdmitArgs, ver string) {
	if a.noRunbookPublish {
		return
	}
	dir := a.skillDir
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".claude", "skills", a.name)
	}
	htmlPath := filepath.Join(dir, "runbook.html")
	metaPath := filepath.Join(dir, "runbook.meta.json")
	_, htmlErr := os.Stat(htmlPath)
	_, metaErr := os.Stat(metaPath)
	if htmlErr != nil && metaErr != nil {
		return // skill ships no runbook, nothing to do
	}
	if htmlErr != nil || metaErr != nil {
		fmt.Fprintln(stderr, "    [runbook] runbook.html / runbook.meta.json present without its pair, not registered.")
		return
	}

	html, err := os.ReadFile(htmlPath)
	if err != nil {
		fmt.Fprintf(stderr, "    [runbook] read %s: %v, not registered.\n", htmlPath, err)
		return
	}
	descriptor, warns, err := loadRunbookDescriptor(metaPath, ver)
	if err != nil {
		fmt.Fprintf(stderr, "    [runbook] %v, not registered.\n", err)
		return
	}
	for _, w := range warns {
		fmt.Fprintf(stderr, "    [runbook] warning: %s\n", w) // BUG-0224: never fatal
	}

	token := os.Getenv("ER1_DEVICE_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "    [runbook] no device token: skipping catalog register (run 'skillctl login').")
		return
	}
	base, _ := er1Endpoint(a.er1Target)
	code, out, err := postRunbookToCatalog(base, token, descriptor, html)
	if err != nil {
		fmt.Fprintf(stderr, "    [runbook] catalog register failed (non-fatal): %v\n", err)
		return
	}
	if code == 200 || code == 201 {
		rbID, _ := descriptor["runbook_id"].(string)
		fmt.Fprintf(stdout, "    [runbook] ✓ registered %s in THOH catalog (%s/thoh)\n", rbID, strings.TrimRight(base, "/"))
		return
	}
	fmt.Fprintf(stderr, "    [runbook] catalog register HTTP %d (non-fatal): %s\n", code, out)
}

// loadRunbookDescriptor reads + validates the sidecar runbook.meta.json. Required:
// runbook_id, title. version is always overridden by the skill version (ver) so the
// skill stays the single source of truth. Pure (no I/O beyond the file read) → unit-tested.
func loadRunbookDescriptor(metaPath, ver string) (map[string]any, []string, error) {
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", metaPath, err)
	}
	return parseRunbookDescriptor(raw, ver)
}

func parseRunbookDescriptor(raw []byte, ver string) (map[string]any, []string, error) {
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, nil, fmt.Errorf("runbook.meta.json is not valid JSON: %w", err)
	}
	if s, _ := d["runbook_id"].(string); strings.TrimSpace(s) == "" {
		return nil, nil, fmt.Errorf(`runbook.meta.json missing required "runbook_id"`)
	}
	if s, _ := d["title"].(string); strings.TrimSpace(s) == "" {
		return nil, nil, fmt.Errorf(`runbook.meta.json missing required "title"`)
	}
	d["version"] = ver // skill is the single source of truth for version
	return d, runbookDescriptorWarnings(d), nil
}

// runbookDescriptorWarnings reports non-fatal gaps in a descriptor (BUG-0224,
// SPEC-0275 section 4.1). It never rejects: a step-less descriptor is a legal
// CATALOG ENTRY, and outlawing it would remove a kind the catalog is meant to
// carry. What it breaks is the silence.
//
// Why a step-less entry matters: THOH derives completion from the required-step
// list, and `_recompute_status` reaches "complete" only via
// `if req and len(done) == len(req)` (aims-core thoh_manager/core.py:143). So an
// execution created against a step-less entry can never leave "assigned". That is
// an unreachable state, not a slow path, and until now nothing said so at publish.
//
// Warnings are RETURNED, not printed: the function stays pure and unit-testable,
// and each caller picks its own channel and prefix.
func runbookDescriptorWarnings(d map[string]any) []string {
	var w []string
	steps, isList := d["steps"].([]any)
	switch {
	case d["steps"] == nil:
		w = append(w, `no "steps": this is a catalog entry, it cannot be assigned and worked to completion`)
	case !isList:
		w = append(w, `"steps" is not a list: it is ignored, so this is a catalog entry only`)
	case len(steps) == 0:
		w = append(w, `"steps" is empty: this is a catalog entry, it cannot be assigned and worked to completion`)
	default:
		seen := map[string]bool{}
		for i, s := range steps {
			m, _ := s.(map[string]any)
			id, _ := m["id"].(string)
			if strings.TrimSpace(id) == "" {
				w = append(w, fmt.Sprintf(`steps[%d] has no "id": it is dropped from the required list`, i))
				continue
			}
			if seen[id] {
				w = append(w, fmt.Sprintf("duplicate step id %q: the catalog validator rejects the descriptor", id))
			}
			seen[id] = true
		}
	}
	return w
}
