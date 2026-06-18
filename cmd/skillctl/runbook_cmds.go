package main

// `skillctl runbook publish` — SPEC-0272: push a generated onboarding runbook
// into the THOH catalog (POST <base>/api/thoh/runbooks).
//
// Why this exists (vs. the tools/skillctl-runbook-publish.sh curl bridge): the
// device token comes from skillctl's OWN keychain item via the FR-0043 autoload
// (autoloadDeviceToken set ER1_DEVICE_TOKEN before we ran) — no `security` CLI
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
	"strings"
	"time"
)

func runRunbook(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "publish" {
		fmt.Fprintln(stderr, "Usage: skillctl runbook publish <runbook.html> --tag <tag> [flags]")
		fmt.Fprintln(stderr, "  Publishes an onboarding runbook into the THOH catalog (SPEC-0272).")
		return 2
	}

	fs := flag.NewFlagSet("runbook publish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tag := fs.String("tag", "", "Release tag the runbook belongs to (e.g. skillctl/v0.2.11-rc3). Version = last path segment. Required.")
	base := fs.String("base", envOr("ER1_API_BASE", "https://onboarding.guide"), "THOH catalog base URL.")
	rbID := fs.String("id", "rb-skillctl-publisher", "Runbook id in the catalog.")
	title := fs.String("title", "skillctl — sign & publish a skill", "Catalog title.")
	purpose := fs.String("purpose", "Turn a person into a verified skill publisher", "One-line purpose.")
	goal := fs.String("goal", "A signed, green-attested skill published to the room", "Completion goal.")
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
	descriptor := map[string]any{
		"runbook_id":       *rbID,
		"version":          version,
		"title":            *title,
		"purpose":          *purpose,
		"goal":             *goal,
		"tags":             []string{"skillctl", "onboarding", "publisher", "trust"},
		"audience_roles":   []string{"user", "learner", "coach"},
		"governance_level": "green",
		"source": map[string]string{
			"repo":    "m3c-tools",
			"path":    "tools/release-templates/skillctl-publisher-runbook.template.html",
			"release": *tag,
		},
		"html_url": fmt.Sprintf("https://github.com/kamir/m3c-tools/releases/download/%s/skillctl-publisher-runbook.html", *tag),
	}
	body, _ := json.Marshal(map[string]any{"descriptor": descriptor, "html": string(html)})

	fmt.Fprintf(stdout, "Runbook : %s@%s — %q\n", *rbID, version, *title)
	fmt.Fprintf(stdout, "HTML    : %s (%d bytes)\n", htmlPath, len(html))
	fmt.Fprintf(stdout, "Catalog : POST %s\n", endpoint)

	if *dryRun {
		pretty, _ := json.MarshalIndent(descriptor, "", "  ")
		fmt.Fprintf(stdout, "\n--dry-run — descriptor that would be posted:\n%s\n", pretty)
		return 0
	}

	token := os.Getenv("ER1_DEVICE_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "runbook publish: no device token — run 'skillctl login' first.")
		return 13
	}

	// 🟡 governed confirm before the prod write.
	if !*yes {
		fmt.Fprintf(stdout, "\n🟡 About to publish into the THOH catalog at %s. Proceed? [y/N] ", *base)
		var resp string
		fmt.Fscanln(os.Stdin, &resp)
		if r := strings.ToLower(strings.TrimSpace(resp)); r != "y" && r != "yes" {
			fmt.Fprintln(stdout, "aborted.")
			return 0
		}
	}

	req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "runbook publish: POST failed: %v\n", err)
		return 1
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	fmt.Fprintf(stdout, "HTTP %d %s\n", res.StatusCode, strings.TrimSpace(string(out)))

	switch res.StatusCode {
	case 200, 201:
		fmt.Fprintf(stdout, "✓ runbook in catalog — assign it from the THOH board (%s/thoh).\n", strings.TrimRight(*base, "/"))
		return 0
	case 401, 403:
		fmt.Fprintln(stderr, "auth rejected — token invalid/expired (re-run 'skillctl login') or not permitted on this catalog.")
		return 13
	default:
		fmt.Fprintln(stderr, "publish failed.")
		return 1
	}
}
