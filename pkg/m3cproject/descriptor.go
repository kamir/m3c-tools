// Package m3cproject resolves the PLM project context for the current working
// directory by reading the SPEC-0214 descriptor file `.m3c/project.yaml` — a
// generated, version-controlled projection of the PLM project object that
// aims-core commits into the repo. Skills (e.g. /session-state, SPEC-0213) use
// this to learn "which PLM project am I in, which ER1 do I talk to, what's the
// tag filter" without guessing.
//
// Resolution order (SPEC-0214 §5 / SPEC-0213 §7bis):
//  1. `.m3c/project.yaml` present (this dir or any ancestor up to the repo root)
//     and schema "m3c.project-descriptor/v1" → authoritative.
//  2. No descriptor → fall back: ProjectID = dir-slug (same convention as
//     /er1-progress-report), ER1 target = "prod", context = "main", no filter.
//  3. Explicit overrides (handled by the caller) beat both.
//
// The ER1 *credential* is never read from here — it resolves via ADR-0003
// (Keychain → Secret Manager → env), keyed by ER1.Target.
package m3cproject

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// DescriptorPath is the descriptor's location relative to the repo root.
const DescriptorPath = ".m3c/project.yaml"

// SchemaV1 is the schema string of the R0 descriptor.
const SchemaV1 = "m3c.project-descriptor/v1"

// Source describes where ProjectID came from.
type Source string

const (
	SourceDescriptor Source = "descriptor"
	SourceDirSlug    Source = "dir-slug"
	SourceOverride   Source = "override"
)

// Descriptor mirrors `.m3c/project.yaml` (SPEC-0214 §3). Unknown future fields
// (e.g. SPEC-0217's `channels:`) are ignored on parse — forward compatible.
type Descriptor struct {
	Schema string `yaml:"schema"`
	Spec   string `yaml:"spec"`

	Plm struct {
		ProjectID   string `yaml:"project_id"`
		Name        string `yaml:"name"`
		Client      string `yaml:"client"`
		ProjectType string `yaml:"project_type"`
		Status      string `yaml:"status"`
	} `yaml:"plm"`

	Repo struct {
		GithubRepoURL  string `yaml:"github_repo_url"`
		SyncTargetPath string `yaml:"sync_target_path"`
	} `yaml:"repo"`

	Memory struct {
		TagFilter     []string `yaml:"tag_filter"`
		DisableFilter bool     `yaml:"disable_filter"`
	} `yaml:"memory"`

	ER1 struct {
		Target  string `yaml:"target"`
		URL     string `yaml:"url"`
		Context string `yaml:"context"`
	} `yaml:"er1"`

	Source struct {
		PLMDocUpdatedAt string `yaml:"plm_doc_updated_at"`
		GeneratedAt     string `yaml:"generated_at"`
		GeneratedBy     string `yaml:"generated_by"`
		CommitSHA       string `yaml:"commit_sha"`
	} `yaml:"source"`

	// runtime-populated (not in the file)
	FoundPath    string `yaml:"-"` // absolute path of the descriptor file, or "" if synthesized
	IDSource     Source `yaml:"-"`
	RepoRoot     string `yaml:"-"` // git toplevel of the working dir, or "" if not a repo
	WorkingDir   string `yaml:"-"`
}

// EffectiveER1Target returns ER1.Target or "prod" (ADR-0003 default).
func (d *Descriptor) EffectiveER1Target() string {
	t := strings.TrimSpace(strings.ToLower(d.ER1.Target))
	if t == "" {
		return "prod"
	}
	return t
}

// EffectiveER1Context returns ER1.Context or "main".
func (d *Descriptor) EffectiveER1Context() string {
	c := strings.TrimSpace(d.ER1.Context)
	if c == "" {
		return "main"
	}
	return c
}

// CommitSHAFromGit returns the SHA of the commit that last touched
// .m3c/project.yaml (the descriptor records its own commit via git history, not
// via the `commit_sha` field which is always null). Empty if not resolvable.
func (d *Descriptor) CommitSHAFromGit() string {
	if d.RepoRoot == "" || d.FoundPath == "" {
		return ""
	}
	cmd := exec.Command("git", "log", "-1", "--format=%H", "--", DescriptorPath)
	cmd.Dir = d.RepoRoot
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// FreshnessUnverified reports whether we can even check staleness — true when
// we have no descriptor or no way to reach the PLM API (the caller decides).
// The actual stale/fresh check (GET /api/plm/projects/<id> vs source
// plm_doc_updated_at) lives in the consumer (SPEC-0214 §6); this package only
// surfaces the inputs.

// findUpwards walks from startDir up to (and including) stopAt looking for rel.
func findUpwards(startDir, rel, stopAt string) (string, bool) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, rel)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, true
		}
		if stopAt != "" && dir == stopAt {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

func gitToplevel(dir string) string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var slugCleaner = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// DirSlug derives the fallback project id from a directory path: the basename,
// sanitized. Mirrors the /er1-progress-report convention closely enough for the
// no-descriptor case (where the id is explicitly marked SourceDirSlug).
func DirSlug(dir string) string {
	base := filepath.Base(strings.TrimRight(dir, string(filepath.Separator)))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "unknown-project"
	}
	s := slugCleaner.ReplaceAllString(base, "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return "unknown-project"
	}
	return s
}

// Load resolves the project context for workingDir.
//
//   - If `.m3c/project.yaml` is found (workingDir or any ancestor up to the git
//     toplevel) and its schema is recognised, it's parsed and returned with
//     IDSource = SourceDescriptor.
//   - Otherwise a synthesized Descriptor is returned: Plm.ProjectID = DirSlug,
//     ER1.Target = "prod", ER1.Context = "main", IDSource = SourceDirSlug.
//
// Load never errors on "no descriptor" — only on a present-but-unparseable file.
func Load(workingDir string) (*Descriptor, error) {
	if workingDir == "" {
		wd, _ := os.Getwd()
		workingDir = wd
	}
	abs, err := filepath.Abs(workingDir)
	if err != nil {
		abs = workingDir
	}
	root := gitToplevel(abs)

	path, found := findUpwards(abs, DescriptorPath, root)
	if !found {
		d := &Descriptor{Schema: SchemaV1}
		d.Plm.ProjectID = DirSlug(root)
		if root == "" {
			d.Plm.ProjectID = DirSlug(abs)
		}
		d.ER1.Target = "prod"
		d.ER1.Context = "main"
		d.IDSource = SourceDirSlug
		d.RepoRoot = root
		d.WorkingDir = abs
		return d, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Descriptor
	if err := yaml.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	if d.Schema != SchemaV1 {
		// Unknown schema — treat as present-but-not-understood. We still return
		// it (with whatever parsed) but mark the id source as descriptor so the
		// caller knows a file exists; a stricter caller can reject on schema.
	}
	if strings.TrimSpace(d.Plm.ProjectID) == "" {
		// Malformed: fall back to dir-slug rather than an empty id.
		d.Plm.ProjectID = DirSlug(root)
		d.IDSource = SourceDirSlug
	} else {
		d.IDSource = SourceDescriptor
	}
	d.FoundPath = path
	d.RepoRoot = root
	d.WorkingDir = abs
	return &d, nil
}
