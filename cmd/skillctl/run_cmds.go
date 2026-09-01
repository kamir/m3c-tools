// run_cmds.go — `skillctl run` (SPEC-0202 P7).
//
// Cooperative wrapper that:
//
//  1. Loads a SPEC-0202 capability token from a file or env var.
//  2. Verifies it against trust roots loaded from ~/.claude/skill-trust-roots.yaml
//     (or --trust-roots).
//  3. Posts a `skill.invoked` event to the audit endpoint (best-effort).
//  4. Forks the requested child process with SKILL_CAPABILITY_TOKEN /
//     SKILL_GATE_AUDIT_URL / SKILL_GATE_API_KEY in the environment.
//  5. Enforces envelope.max_runtime_seconds with a kill-then-exit-38 path.
//  6. Posts a `skill.completed` event with duration + exit_code (best-effort).
//
// Cooperative model only: no LD_PRELOAD / DYLD_INSERT_LIBRARIES. The gate
// library (pkg/skillgate) is in-process for whatever child opts into it.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// printRunUsage prints the `skillctl run` help text.
func printRunUsage() {
	fmt.Print(`skillctl run — cooperative SPEC-0202 invocation wrapper

Usage:
  skillctl run --token <file|env:VAR> --target <prod|stage|local>
               [--audit-url <url>] [--api-key-from <file>]
               [--trust-roots <file>] -- <cmd> [args...]

Required:
  --token <src>       Capability token JSON. Either a file path or "env:<VAR>".

Optional:
  --target <env>      Audit target: prod | stage | local (default: local).
  --audit-url <url>   Override audit URL (otherwise derived from --target).
  --api-key-from <f>  File containing API key for audit POSTs.
                      Default: ~/.claude/api-key (read if present, else empty).
  --trust-roots <f>   Trust roots file (YAML/JSON).
                      Default: ~/.claude/skill-trust-roots.yaml. Required.

Behavior:
  - Verifies the token against trust roots; fails closed on missing/invalid.
  - Posts skill.invoked / skill.completed events (best-effort).
  - Sets SKILL_CAPABILITY_TOKEN, SKILL_GATE_AUDIT_URL, SKILL_GATE_API_KEY
    in the child's environment.
  - Enforces envelope.max_runtime_seconds (exit 38 on timeout).

Exit codes (SPEC-0202 §8.2):
  30  capability_missing       34  bad_signature / unknown_issuer / envelope_grew
  31  token_not_found          35  token_expired
  33  subprocess_denied        37  invalid_signature (alias)
                                38  runtime_quota_exceeded
                                127 child not found
`)
}

// runRun is the entrypoint for `skillctl run`. Returns the OS exit code.
func runRun(args []string) int {
	tokenSrc := ""
	target := "local"
	auditURL := ""
	apiKeyFrom := ""
	trustRootsPath := ""
	var childArgv []string

	// Parse flags up to "--"; everything after "--" is the child argv.
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			childArgv = args[i+1:]
			break
		}
		switch a {
		case "--token":
			if i+1 < len(args) {
				i++
				tokenSrc = args[i]
			}
		case "--target":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case "--audit-url":
			if i+1 < len(args) {
				i++
				auditURL = args[i]
			}
		case "--api-key-from":
			if i+1 < len(args) {
				i++
				apiKeyFrom = args[i]
			}
		case "--trust-roots":
			if i+1 < len(args) {
				i++
				trustRootsPath = args[i]
			}
		case "-h", "--help":
			printRunUsage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "skillctl run: unknown flag: %s\n", a)
			printRunUsage()
			return 2
		}
	}

	if tokenSrc == "" {
		fmt.Fprintln(os.Stderr, "skillctl run: --token is required")
		return 2
	}
	if len(childArgv) == 0 {
		fmt.Fprintln(os.Stderr, "skillctl run: missing child command after --")
		return 2
	}

	// 1. Load token.
	tokenJSON, err := loadTokenSource(tokenSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl run: %v\n", err)
		return skillgate.ExitDataSourceMissing // 31
	}
	var tok skillgate.Token
	if err := json.Unmarshal(tokenJSON, &tok); err != nil {
		fmt.Fprintf(os.Stderr, "skillctl run: parse token JSON: %v\n", err)
		return skillgate.ExitInvalidSignature // 37 — malformed maps to invalid
	}

	// 2. Load trust roots.
	if trustRootsPath == "" {
		home, _ := os.UserHomeDir()
		trustRootsPath = filepath.Join(home, ".claude", "skill-trust-roots.yaml")
	}
	roots, err := loadTrustRoots(trustRootsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl run: trust roots: %v\n", err)
		fmt.Fprintf(os.Stderr, "  provision the file at %s with one entry per registry key:\n", trustRootsPath)
		fmt.Fprintln(os.Stderr, "    registry_keys:")
		fmt.Fprintln(os.Stderr, "      <key_id>: <base64-or-hex ed25519 public key>")
		return skillgate.ExitInvalidSignature // 37
	}

	// 3. Verify.
	res := skillgate.Verify(&tok, roots)
	if !res.OK {
		fmt.Fprintf(os.Stderr, "skillctl run: token verify failed: %s\n", res.Reason)
		return verifyReasonToExit(res.Reason)
	}

	// 4. Resolve audit URL + API key.
	if auditURL == "" {
		auditURL = defaultAuditURL(target)
	}
	apiKey := resolveAPIKey(apiKeyFrom)

	// 5. Post skill.invoked (best-effort). ALSO append a device-signed record to
	// the durable local trail (SPEC-0202 §9) — the wrapper-level invocation
	// event joins the same Art.12 trail the hook + the gate's SignedSink write.
	// The HTTP post is best-effort; the signed trail is the durable record.
	requestedCmd := strings.Join(childArgv, " ")
	postRunEvent(auditURL, apiKey, target, "skill.invoked", &tok, requestedCmd, 0, 0)
	runHome, _ := userHome()
	appendSignedInvocation(runHome, skillgate.InvocationRecord{
		EventType:    "skill.invoked",
		SkillDigest:  tok.BundleDigest,
		SkillName:    tok.SkillName,
		SkillVersion: tok.SkillVersion,
		Action:       "invoke",
		Tool:         requestedCmd,
		TokenID:      tok.TokenID,
		SessionID:    tok.CallerSession,
		ExitCode:     0,
	})

	// 6. Build child env.
	env := os.Environ()
	env = appendOrReplaceEnv(env, "SKILL_CAPABILITY_TOKEN", string(tokenJSON))
	env = appendOrReplaceEnv(env, "SKILL_GATE_AUDIT_URL", auditURL)
	if apiKey != "" {
		env = appendOrReplaceEnv(env, "SKILL_GATE_API_KEY", apiKey)
	}

	// 7. Run child with optional max-runtime.
	start := time.Now()
	exitCode := runChild(childArgv, env, tok.Envelope.MaxRuntimeSeconds)
	dur := time.Since(start)

	// 8. Post skill.completed (best-effort) + signed completion record.
	postRunEvent(auditURL, apiKey, target, "skill.completed", &tok, requestedCmd,
		exitCode, dur.Milliseconds())
	appendSignedInvocation(runHome, skillgate.InvocationRecord{
		EventType:    "skill.completed",
		SkillDigest:  tok.BundleDigest,
		SkillName:    tok.SkillName,
		SkillVersion: tok.SkillVersion,
		Action:       "complete",
		Tool:         requestedCmd,
		TokenID:      tok.TokenID,
		SessionID:    tok.CallerSession,
		ExitCode:     exitCode,
	})

	return exitCode
}

// runChild executes argv with env, returning its exit code. If maxRuntime > 0,
// the child is killed after that many seconds and exit 38 is returned.
func runChild(argv []string, env []string, maxRuntimeSec int) int {
	ctx := context.Background()
	var cancel context.CancelFunc
	timedOut := false
	if maxRuntimeSec > 0 {
		ctx, cancel = context.WithTimeout(context.Background(),
			time.Duration(maxRuntimeSec)*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	// Detect timeout: ctx.Err() == DeadlineExceeded means we killed it.
	if maxRuntimeSec > 0 && ctx.Err() == context.DeadlineExceeded {
		timedOut = true
	}
	if timedOut {
		fmt.Fprintf(os.Stderr, "skillctl run: max_runtime_seconds=%d exceeded; child killed\n", maxRuntimeSec)
		return skillgate.ExitRuntimeQuota // 38
	}
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	// "executable file not found in $PATH" → 127 (sh convention).
	if strings.Contains(err.Error(), "executable file not found") ||
		strings.Contains(err.Error(), "no such file or directory") {
		fmt.Fprintf(os.Stderr, "skillctl run: %v\n", err)
		return 127
	}
	fmt.Fprintf(os.Stderr, "skillctl run: child error: %v\n", err)
	return 1
}

// loadTokenSource reads a token from "file:..." (default) or "env:<VAR>".
func loadTokenSource(src string) ([]byte, error) {
	if strings.HasPrefix(src, "env:") {
		v := os.Getenv(strings.TrimPrefix(src, "env:"))
		if v == "" {
			return nil, fmt.Errorf("token env var %s is empty", strings.TrimPrefix(src, "env:"))
		}
		return []byte(v), nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("token file: %w", err)
	}
	return data, nil
}

// loadTrustRoots reads a minimal YAML or JSON file with shape:
//
//	registry_keys:
//	  <key_id>: <base64-or-hex ed25519 public key (32 bytes)>
//
// We don't pull a YAML dep; the parser is line-based and supports the simple
// 2-level shape above. JSON files are also accepted.
func loadTrustRoots(path string) (*skillgate.TrustRoots, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	roots := &skillgate.TrustRoots{RegistryKeys: map[string][]byte{}}

	// Try JSON first.
	var jdoc struct {
		RegistryKeys map[string]string `json:"registry_keys"`
	}
	if json.Unmarshal(data, &jdoc) == nil && len(jdoc.RegistryKeys) > 0 {
		for kid, encoded := range jdoc.RegistryKeys {
			pub, err := decodePubKey(encoded)
			if err != nil {
				return nil, fmt.Errorf("registry_key %q: %w", kid, err)
			}
			roots.RegistryKeys[kid] = pub
		}
		return roots, nil
	}

	// Fall back to a tiny YAML subset: top-level "registry_keys:" then
	// indented "<key>: <value>" entries.
	lines := strings.Split(string(data), "\n")
	inSection := false
	for _, raw := range lines {
		// Strip comments after a '#' that isn't inside the value.
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = raw[:i]
		}
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Top-level key.
			if strings.HasPrefix(strings.TrimSpace(line), "registry_keys:") {
				inSection = true
				continue
			}
			inSection = false
			continue
		}
		if !inSection {
			continue
		}
		trim := strings.TrimSpace(line)
		idx := strings.Index(trim, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(trim[:idx])
		val := strings.TrimSpace(trim[idx+1:])
		val = strings.Trim(val, `"'`)
		if key == "" || val == "" {
			continue
		}
		pub, err := decodePubKey(val)
		if err != nil {
			return nil, fmt.Errorf("registry_key %q: %w", key, err)
		}
		roots.RegistryKeys[key] = pub
	}

	if len(roots.RegistryKeys) == 0 {
		return nil, fmt.Errorf("no registry_keys found in %s", path)
	}
	return roots, nil
}

// decodePubKey accepts either base64 or hex encodings and returns 32 bytes.
func decodePubKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	return nil, fmt.Errorf("not base64/hex ed25519 (expected %d bytes)", ed25519.PublicKeySize)
}

// verifyReasonToExit maps skillgate verify reasons to SPEC-0202 §8.2 exit
// codes. The mapping is deliberately conservative: anything that smells
// like signature/issuer/envelope tampering → 34/37; expiry → 35.
func verifyReasonToExit(reason string) int {
	switch reason {
	case "expired":
		return skillgate.ExitTokenExpired // 35
	case "bad_signature":
		return skillgate.ExitFileOutsideEnv // 34 (mapped per task spec)
	case "unknown_issuer":
		return skillgate.ExitFileOutsideEnv // 34
	case "envelope_grew", "expires_extended", "denylist_shrunk", "destructive_added",
		"chain_too_deep", "missing_parent_link":
		return skillgate.ExitFileOutsideEnv // 34
	case "malformed":
		return skillgate.ExitInvalidSignature // 37
	default:
		return skillgate.ExitInvalidSignature // 37
	}
}

// defaultAuditURL maps --target → URL.
//
//	prod  → https://onboarding.guide
//	stage → from STAGE_URL in tools/config/deploy.env (best-effort) or
//	        https://youtube-summarizer-mvp-v1-bf2osjjeqa-lz.a.run.app
//	local → https://127.0.0.1:8081
func defaultAuditURL(target string) string {
	switch target {
	case "prod":
		return "https://onboarding.guide/api/skills/runtime/invocations"
	case "stage":
		base := readDeployEnvStageURL()
		if base == "" {
			base = "https://youtube-summarizer-mvp-v1-bf2osjjeqa-lz.a.run.app"
		}
		return strings.TrimRight(base, "/") + "/api/skills/runtime/invocations"
	default: // local
		return "https://127.0.0.1:8081/api/skills/runtime/invocations"
	}
}

// readDeployEnvStageURL is best-effort. Looks for tools/config/deploy.env
// relative to a few likely roots. Returns "" if not found.
func readDeployEnvStageURL() string {
	candidates := []string{
		"tools/config/deploy.env",
		"../tools/config/deploy.env",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "GITHUB.active/my-ai-X/aims-core/tools/config/deploy.env"))
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "STAGE_URL=") {
				v := strings.TrimPrefix(line, "STAGE_URL=")
				return strings.Trim(v, `"'`)
			}
		}
	}
	return ""
}

// resolveAPIKey reads the file given by --api-key-from, falling back to the
// default ~/.claude/api-key. Returns "" if not present.
func resolveAPIKey(explicit string) string {
	path := explicit
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".claude", "api-key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// runEvent is the JSON payload posted to /api/skills/runtime/invocations
// for skill.invoked / skill.completed. It mirrors skillgate.InvocationEvent
// but adds duration + exit fields specific to the wrapper.
type runEvent struct {
	Type         string `json:"type"`
	TokenID      string `json:"token_id"`
	SkillName    string `json:"skill_name"`
	Tenant       string `json:"tenant"`
	Timestamp    string `json:"timestamp"`
	RequestedCmd string `json:"requested_cmd,omitempty"`
	ExitCode     int    `json:"exit_code,omitempty"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
}

// postRunEvent fires-and-forgets. Errors are logged to stderr and ignored
// (cooperative model — audit MUST NOT block the wrapper).
func postRunEvent(url, apiKey, target, evType string, tok *skillgate.Token,
	cmd string, exitCode int, durationMS int64) {
	if url == "" {
		return
	}
	ev := runEvent{
		Type:         evType,
		TokenID:      tok.TokenID,
		SkillName:    tok.SkillName,
		Tenant:       tok.TenantScope,
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		RequestedCmd: cmd,
		ExitCode:     exitCode,
		DurationMS:   durationMS,
	}
	body, err := json.Marshal(ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl run: warn: marshal event: %v\n", err)
		return
	}
	client := newHTTPClient(target)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl run: warn: build audit request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}
	ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
	defer cancel()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillctl run: warn: audit POST: %v\n", err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// newHTTPClient returns an http.Client. For --target=local, TLS verification
// is skipped (self-signed dev cert). For prod/stage, default verification.
func newHTTPClient(target string) *http.Client {
	if target == "local" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local dev only
		}
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	return &http.Client{Timeout: 3 * time.Second}
}

// appendOrReplaceEnv replaces KEY= entries in env or appends KEY=VAL.
func appendOrReplaceEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}
