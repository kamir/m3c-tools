// Package session implements the SPEC-0213 "session-state in ER1" model for
// non-Claude-Code callers — the Go mirror of the `/session-state` skill, exposed
// as `skillctl session <open|checkpoint|close|resume|list|show>`. It reuses
// pkg/er1 (upload) and pkg/m3cproject (project-context resolution, SPEC-0214).
//
// A session-state item is one ER1 memory item per working session, written via
// /upload_2. Checkpoints are linked child items (link/parent/<ctx>/<id> +
// link/checkpoint/<ctx>/<id>). The transcript stays local — only a
// local-session://<host>/<session_id> pointer is written.
package session

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/m3cproject"
)

// ---------------------------------------------------------------------------
// identity / environment
// ---------------------------------------------------------------------------

// Ident is the resolved identity for a session — descriptor-derived where
// possible, with the SPEC-0213 fallbacks.
type Ident struct {
	SessionID  string
	Project    string // PLM project id (or dir-slug fallback)
	ProjectSrc string // descriptor | dir-slug | override
	CwdSlug    string
	Cwd        string
	Host       string // short hostname (SPEC-0195 derivation)
	Device     string // INFRA/devices/ id, or ""
	CW         string // ISO calendar week, e.g. 2026-W20
	ER1Target  string
	ER1Context string
	Branch     string
	Head       string
	Dirty      bool
	Ahead      int
	Descriptor *m3cproject.Descriptor
}

var slugClean = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func slugify(s string) string {
	s = slugClean.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return "unknown"
	}
	return s
}

func shortHost() string {
	h, _ := os.Hostname()
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	if h == "" {
		return "unknown-host"
	}
	return h
}

// deviceFor looks up the host in the INFRA/devices/ registry (m3c-tools-maintenance);
// returns "" if not found / not present.
func deviceFor(host string) string {
	candidates := []string{
		os.Getenv("M3C_DEVICES_DIR"),
		"/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/INFRA/devices",
	}
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		re := regexp.MustCompile(`(^|[^a-zA-Z0-9-])` + regexp.QuoteMeta(host) + `([^a-zA-Z0-9-]|$)`)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if re.Match(b) || re.MatchString(e.Name()) {
				name := e.Name()
				if i := strings.LastIndexByte(name, '.'); i > 0 {
					name = name[:i]
				}
				return name
			}
		}
	}
	return ""
}

func gitOut(dir string, args ...string) string {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ResolveIdent gathers the session identity for workingDir, applying explicit
// overrides (sessionID/project/er1Target/er1Context — any may be "" to skip).
func ResolveIdent(workingDir, sessionID, project, er1Target, er1Context string) (*Ident, error) {
	if workingDir == "" {
		wd, _ := os.Getwd()
		workingDir = wd
	}
	d, err := m3cproject.Load(workingDir)
	if err != nil {
		return nil, err
	}
	id := &Ident{Descriptor: d, Cwd: workingDir}

	id.SessionID = strings.TrimSpace(sessionID)
	if id.SessionID == "" {
		id.SessionID = strings.TrimSpace(os.Getenv("CLAUDE_SESSION_ID"))
	}
	if id.SessionID == "" {
		id.SessionID = uuid.NewString()
	}

	id.Project = strings.TrimSpace(project)
	if id.Project != "" {
		id.ProjectSrc = "override"
	} else {
		id.Project = d.Plm.ProjectID
		id.ProjectSrc = string(d.IDSource)
	}

	id.CwdSlug = slugify(filepath.Base(strings.TrimRight(workingDir, string(filepath.Separator))))
	id.Host = shortHost()
	id.Device = deviceFor(id.Host)
	id.CW = isoWeek()

	id.ER1Target = strings.TrimSpace(er1Target)
	if id.ER1Target == "" {
		id.ER1Target = d.EffectiveER1Target()
	}
	id.ER1Context = strings.TrimSpace(er1Context)
	if id.ER1Context == "" {
		id.ER1Context = d.EffectiveER1Context()
	}

	root := d.RepoRoot
	if root == "" {
		root = workingDir
	}
	id.Branch = orVal(gitOut(root, "rev-parse", "--abbrev-ref", "HEAD"), "?")
	id.Head = orVal(gitOut(root, "rev-parse", "--short", "HEAD"), "?")
	id.Dirty = gitOut(root, "status", "--porcelain") != ""
	id.Ahead = atoiOr(gitOut(root, "rev-list", "--count", "@{u}..HEAD"), 0)
	return id, nil
}

func orVal(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
func atoiOr(s string, def int) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if strings.TrimSpace(s) == "" {
		return def
	}
	return n
}

func isoWeek() string {
	y, w := time.Now().UTC().ISOWeek()
	return fmt.Sprintf("%04d-W%02d", y, w)
}

// transcriptPointer is the local-session:// pointer (never the bytes).
func (id *Ident) transcriptPointer() string {
	return fmt.Sprintf("local-session://%s/%s", id.Host, id.SessionID)
}

// ---------------------------------------------------------------------------
// ER1 wiring
// ---------------------------------------------------------------------------

// ER1Endpoint resolves the ER1 base URL for a target (ADR-0003 matrix).
func ER1Endpoint(target string) (baseURL string, verifySSL bool) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "", "prod":
		return "https://onboarding.guide", true
	case "local":
		return "https://127.0.0.1:8081", false
	}
	if strings.HasPrefix(target, "http") {
		return strings.TrimRight(target, "/"), !strings.Contains(target, "127.0.0.1") && !strings.Contains(target, "localhost")
	}
	// stage / unknown: fall back to whatever ER1_API_URL says, else prod
	if u := os.Getenv("ER1_API_URL"); u != "" {
		base := strings.TrimRight(strings.TrimSuffix(u, "/upload_2"), "/")
		verify := os.Getenv("ER1_VERIFY_SSL") != "false"
		// SEC-M7: only honour insecure for loopback; force verification on for remote.
		if !verify && !strings.Contains(base, "127.0.0.1") && !strings.Contains(base, "localhost") {
			verify = true
		}
		return base, verify
	}
	return "https://onboarding.guide", true
}

// resolveAPIKey: env ER1_API_KEY → macOS Keychain `aims-core-er1` (ADR-0003).
func resolveAPIKey() string {
	if k := os.Getenv("ER1_API_KEY"); k != "" {
		return k
	}
	u, _ := user.Current()
	uname := "kamir"
	if u != nil && u.Username != "" {
		uname = u.Username
	}
	out, err := exec.Command("security", "find-generic-password", "-s", "aims-core-er1", "-a", uname, "-w").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// er1Config builds a pkg/er1.Config pointed at the session's ER1 target.
func (id *Ident) er1Config() (*er1.Config, error) {
	base, verify := ER1Endpoint(id.ER1Target)
	cfg := er1.LoadConfig()
	cfg.APIURL = base + "/upload_2"
	cfg.VerifySSL = verify
	if cfg.APIKey == "" {
		cfg.APIKey = resolveAPIKey()
	}
	if cfg.APIKey == "" && os.Getenv("ER1_DEVICE_TOKEN") == "" {
		return nil, fmt.Errorf("no ER1 credential — set ER1_API_KEY or add the `aims-core-er1` Keychain item (ADR-0003)")
	}
	return cfg, nil
}

// uploadItem POSTs a text item to /upload_2 with the given tags; returns its doc_id.
func uploadItem(cfg *er1.Config, body, filename, tags, contentType string) (string, error) {
	resp, err := er1.Upload(cfg, &er1.UploadPayload{
		TranscriptData:     []byte(body),
		TranscriptFilename: filename,
		Tags:               tags,
		ContentType:        contentType,
	})
	if err != nil {
		return "", err
	}
	return resp.DocID, nil
}

// httpGetJSON does a best-effort GET against the ER1 base URL + path, returning
// the decoded JSON (as a generic value) or an error.
func httpGetJSON(target, path string) (any, error) {
	base, verify := ER1Endpoint(target)
	apiKey := resolveAPIKey()
	client := &http.Client{Timeout: 15 * time.Second}
	if !verify {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}
	if tok := os.Getenv("ER1_DEVICE_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s -> HTTP %d", path, resp.StatusCode)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return v, nil
}

// searchByTags queries ER1 for items carrying ALL of tags. Best-effort — returns
// a list of item maps (whatever shape the server gives) or an error.
func searchByTags(ctxID, target string, tags []string) ([]map[string]any, error) {
	q := url.Values{}
	q.Set("tags", strings.Join(tags, ","))
	v, err := httpGetJSON(target, "/memory/"+url.PathEscape(ctxID)+"/search?"+q.Encode())
	if err != nil {
		return nil, err
	}
	return coerceItems(v), nil
}

func coerceItems(v any) []map[string]any {
	switch x := v.(type) {
	case []any:
		return toMapList(x)
	case map[string]any:
		for _, key := range []string{"items", "results", "memories", "docs"} {
			if inner, ok := x[key].([]any); ok {
				return toMapList(inner)
			}
		}
		return []map[string]any{x}
	}
	return nil
}
func toMapList(xs []any) []map[string]any {
	out := make([]map[string]any, 0, len(xs))
	for _, e := range xs {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// item construction (SPEC-0213 §5 / §6)
// ---------------------------------------------------------------------------

func ynull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

// SessionStateBody renders the session-state item body (YAML frontmatter + md).
func (id *Ident) SessionStateBody(intent, continuesFrom, model string) string {
	cw := isoWeek()
	if model == "" {
		model = "skillctl"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "---\nspec: SPEC-0213\nkind: session-state\nsession_id: %s\n", id.SessionID)
	fmt.Fprintf(&b, "project: %s\nproject_id_source: %s\n", id.Project, id.ProjectSrc)
	fmt.Fprintf(&b, "cwd: %s\ncwd_slug: %s\nhost: %s\ndevice: %s\n", id.Cwd, id.CwdSlug, id.Host, ynull(id.Device))
	fmt.Fprintf(&b, "er1_target: %s\ner1_context: %s\n", id.ER1Target, id.ER1Context)
	fmt.Fprintf(&b, "descriptor_sha: %s\n", ynull(id.Descriptor.CommitSHAFromGit()))
	fmt.Fprintf(&b, "transcript_pointer: %s\nopened_at: %s\ncontinues_from: %s\n",
		id.transcriptPointer(), time.Now().UTC().Format(time.RFC3339), ynull(continuesFrom))
	fmt.Fprintf(&b, "git: { branch: %s, head: %s, dirty: %v, ahead: %d }\nopened_by: %s\ncw: %s\n---\n\n",
		id.Branch, id.Head, id.Dirty, id.Ahead, model, cw)
	fmt.Fprintf(&b, "# Session — %s @ %s — %s\n\n", id.Project, id.Host, time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "**Opened:** %s · **Branch:** %s @ %s (dirty: %v) · **Transcript:** `%s`\n",
		time.Now().UTC().Format("2006-01-02 15:04 UTC"), id.Branch, id.Head, id.Dirty, id.transcriptPointer())
	fmt.Fprintf(&b, "**Continues from:** %s\n\n## Intent\n%s\n\n## Checkpoints\n_(linked child items — see the memory viewer's Comments card)_\n",
		orVal(continuesFrom, "_(none)_"), orVal(intent, "—"))
	return b.String()
}

// SessionStateTags returns the tag set for the session-state item.
func (id *Ident) SessionStateTags(continuesFrom string) []string {
	t := []string{
		"claude-code.session",
		"session:" + id.SessionID,
		"project:" + id.Project,
		"cwd:" + id.CwdSlug,
		"host:" + id.Host,
		"cw:" + isoWeek(),
		"claude-code.session.open",
	}
	if id.Device != "" {
		t = append(t, "device:"+id.Device)
	}
	if continuesFrom != "" {
		// continuesFrom is "<ctx>/<doc_id>"
		t = append(t, "link/continues/"+continuesFrom)
	}
	return t
}

// CheckpointBody renders a checkpoint child item body.
func (id *Ident) CheckpointBody(note string, closing bool, gitDiffStat, todos, filesTouched string) string {
	var b strings.Builder
	title := "Checkpoint"
	if closing {
		title = "Checkpoint (close)"
	}
	fmt.Fprintf(&b, "# %s — %s — %s @ %s\n\n", title, time.Now().UTC().Format("2006-01-02 15:04 UTC"), id.Project, id.Host)
	fmt.Fprintf(&b, "**git:** { branch: %s, head: %s, dirty: %v, ahead: %d }\n\n", id.Branch, id.Head, id.Dirty, id.Ahead)
	if note != "" {
		fmt.Fprintf(&b, "## Note\n%s\n\n", note)
	}
	if gitDiffStat != "" {
		fmt.Fprintf(&b, "## Changes since last checkpoint (git diff --stat)\n```\n%s\n```\n\n", gitDiffStat)
	}
	if todos != "" {
		fmt.Fprintf(&b, "## Open\n%s\n\n", todos)
	}
	if filesTouched != "" {
		fmt.Fprintf(&b, "## Files touched\n```\n%s\n```\n", filesTouched)
	}
	if b.Len() == 0 {
		b.WriteString("_(no changes)_\n")
	}
	return b.String()
}

// CheckpointTags returns the tag set for a checkpoint child of sessionDocID in ctxID.
func (id *Ident) CheckpointTags(ctxID, sessionDocID string, closing, distilled bool) []string {
	t := []string{
		"claude-code.checkpoint",
		"link/parent/" + ctxID + "/" + sessionDocID,
		"link/checkpoint/" + ctxID + "/" + sessionDocID,
		"session:" + id.SessionID,
		"project:" + id.Project,
		"cwd:" + id.CwdSlug,
		"host:" + id.Host,
		"cw:" + isoWeek(),
	}
	if closing {
		t = append(t, "claude-code.checkpoint.close")
	}
	if distilled {
		t = append(t, "auto:generated")
	}
	return t
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

// OpenOpts configures Open.
type OpenOpts struct {
	WorkingDir    string
	SessionID     string // override
	Project       string // override
	ER1Target     string // override
	ER1Context    string // override
	Intent        string
	ContinuesFrom string // "<ctx>/<doc_id>" to thread the chain
	Model         string
}

// OpenResult is what Open returns.
type OpenResult struct {
	DocID         string
	AlreadyExists bool
	Ident         *Ident
}

// Open creates the session-state item (idempotent on session:<uuid>). It does
// NOT itself secret-scan the body — there's nothing user-authored that isn't a
// harness fact; callers that pass a free-form --intent should sanitize it.
func Open(o OpenOpts) (*OpenResult, error) {
	id, err := ResolveIdent(o.WorkingDir, o.SessionID, o.Project, o.ER1Target, o.ER1Context)
	if err != nil {
		return nil, err
	}
	cfg, err := id.er1Config()
	if err != nil {
		return nil, err
	}
	// idempotency: already an open item for this session?
	if existing, _ := searchByTags(cfg.ContextID, id.ER1Target, []string{"claude-code.session", "session:" + id.SessionID}); len(existing) > 0 {
		if doc := firstDocID(existing); doc != "" {
			return &OpenResult{DocID: doc, AlreadyExists: true, Ident: id}, nil
		}
	}
	body := id.SessionStateBody(o.Intent, o.ContinuesFrom, o.Model)
	if hits := scanSecrets(body); len(hits) > 0 {
		return nil, fmt.Errorf("refusing to write session-state item — secret-shaped content: %v", hits)
	}
	tags := id.SessionStateTags(o.ContinuesFrom)
	doc, err := uploadItem(cfg, body, "session-"+id.SessionID+".md", strings.Join(tags, ","), "text-note")
	if err != nil {
		return nil, err
	}
	appendWlogPointer(id, fmt.Sprintf("session %s opened — ER1 doc %s @ %s", id.SessionID, doc, id.ER1Target))
	return &OpenResult{DocID: doc, Ident: id}, nil
}

// CheckpointOpts configures Checkpoint / Close.
type CheckpointOpts struct {
	WorkingDir string
	SessionID  string // override (else env / new uuid won't match an existing session — caller should pass it)
	Project    string
	ER1Target  string
	ER1Context string
	Note       string
	Auto       bool // build a diff/todo snapshot rather than prose
	Closing    bool // adds claude-code.checkpoint.close
	Distilled  bool // adds auto:generated (close --distill)
	Todos      string
}

// CheckpointResult is what Checkpoint returns.
type CheckpointResult struct {
	DocID        string
	SessionDocID string
	Skipped      bool
	SkipReason   string
	Ident        *Ident
}

// Checkpoint appends a checkpoint child item to the session-state item. Requires
// an existing session-state item for the session (caller should run Open first).
func Checkpoint(o CheckpointOpts) (*CheckpointResult, error) {
	id, err := ResolveIdent(o.WorkingDir, o.SessionID, o.Project, o.ER1Target, o.ER1Context)
	if err != nil {
		return nil, err
	}
	cfg, err := id.er1Config()
	if err != nil {
		return nil, err
	}
	existing, _ := searchByTags(cfg.ContextID, id.ER1Target, []string{"claude-code.session", "session:" + id.SessionID})
	sessionDoc := firstDocID(existing)
	if sessionDoc == "" {
		return nil, fmt.Errorf("no open session-state item for session:%s — run `skillctl session open` first", id.SessionID)
	}

	var gitDiffStat, filesTouched string
	if o.Auto {
		root := id.Descriptor.RepoRoot
		if root == "" {
			root = id.Cwd
		}
		gitDiffStat = gitOut(root, "diff", "--stat", "HEAD~1..HEAD")
		filesTouched = gitOut(root, "status", "--porcelain")
		if strings.TrimSpace(gitDiffStat) == "" && strings.TrimSpace(filesTouched) == "" && strings.TrimSpace(o.Todos) == "" && !o.Closing {
			return &CheckpointResult{Skipped: true, SkipReason: "no changes since last checkpoint", SessionDocID: sessionDoc, Ident: id}, nil
		}
	}
	body := id.CheckpointBody(o.Note, o.Closing, gitDiffStat, o.Todos, filesTouched)
	if hits := scanSecrets(body); len(hits) > 0 {
		return nil, fmt.Errorf("refusing to write checkpoint — secret-shaped content: %v", hits)
	}
	tags := id.CheckpointTags(cfg.ContextID, sessionDoc, o.Closing, o.Distilled)
	doc, err := uploadItem(cfg, body, "checkpoint-"+id.SessionID+"-"+time.Now().UTC().Format("20060102T150405")+".md", strings.Join(tags, ","), "text-note")
	if err != nil {
		return nil, err
	}
	return &CheckpointResult{DocID: doc, SessionDocID: sessionDoc, Ident: id}, nil
}

// ListOpts configures List.
type ListOpts struct {
	WorkingDir string
	Project    string // "" = the descriptor's project
	Host       string
	ER1Target  string
	OpenOnly   bool
}

// SessionRow is a row in the list output.
type SessionRow struct {
	DocID string
	Tags  []string
	Title string
	Item  map[string]any
}

// List returns the session-state items matching the filter. Best-effort over the
// ER1 search endpoint — returns an error (with a hint) if the endpoint is down.
func List(o ListOpts) ([]SessionRow, error) {
	id, err := ResolveIdent(o.WorkingDir, "", o.Project, o.ER1Target, "")
	if err != nil {
		return nil, err
	}
	cfg := er1.LoadConfig()
	if cfg.ContextID == "" {
		cfg.ContextID = "107677460544181387647___mft"
	}
	tags := []string{"claude-code.session"}
	if id.Project != "" {
		tags = append(tags, "project:"+id.Project)
	}
	if o.Host != "" {
		tags = append(tags, "host:"+o.Host)
	}
	items, err := searchByTags(cfg.ContextID, id.ER1Target, tags)
	if err != nil {
		return nil, fmt.Errorf("%w (the ER1 search endpoint may be unavailable — for interactive browsing use the `/session-state` skill or the memory viewer)", err)
	}
	rows := make([]SessionRow, 0, len(items))
	for _, it := range items {
		row := SessionRow{DocID: stringField(it, "doc_id", "id"), Tags: stringSlice(it["tags"]), Item: it}
		if o.OpenOnly && hasTag(row.Tags, "claude-code.session.closed") {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func firstDocID(items []map[string]any) string {
	for _, it := range items {
		if d := stringField(it, "doc_id", "id"); d != "" {
			return d
		}
	}
	return ""
}

func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func stringSlice(v any) []string {
	xs, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, e := range xs {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

// scanSecrets — a small belt-and-suspenders check (mirrors the server-side
// project_descriptor.scan_for_secrets patterns). Returns matched pattern names.
var secretPats = []struct {
	name string
	re   *regexp.Regexp
}{
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`)},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{30,45}\b`)},
	{"private_key_block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"generic_api_key_kv", regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|password|passwd|token|bearer)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-./+]{16,}['"]?`)},
}

func scanSecrets(text string) []string {
	var hits []string
	for _, p := range secretPats {
		if p.re.MatchString(text) {
			hits = append(hits, p.name)
		}
	}
	return hits
}

// appendWlogPointer best-effort writes a pointer line to <repoRoot>/WLOG/session-state.log.
func appendWlogPointer(id *Ident, line string) {
	root := id.Descriptor.RepoRoot
	if root == "" {
		return
	}
	wdir := filepath.Join(root, "WLOG")
	if st, err := os.Stat(wdir); err != nil || !st.IsDir() {
		return
	}
	f, err := os.OpenFile(filepath.Join(wdir, "session-state.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "- %s %s\n", time.Now().UTC().Format(time.RFC3339), line)
}
