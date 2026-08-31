package git

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

func init() {
	artifact.Register("gitlab", openGitLab)
	artifact.Register("github", openGitHub)
}

// openGitLab maps gitlab://<host>/<group>/<proj>[@ref] → https://…/….git.
// Credential injection is via opts.Creds (SPEC-0356 D5). Publishing PUSHES, so
// it needs a WRITE-capable credential — a GitLab **Project Access Token** (or a
// personal access token / write deploy key), NOT a Deploy Token: GitLab rejects
// write_repository as a deploy-token scope, and the default branch is protected
// at Maintainer (push level 40). The oauth2:<token>@host form used below works
// unchanged for a project/personal token, so no code change is required.
func openGitLab(spec string, opts artifact.OpenOptions) (artifact.Backend, error) {
	remote, err := gitRemoteFromSpec(spec, "gitlab://")
	if err != nil {
		return nil, err
	}
	// Lab convenience: an on-prem/self-hosted GitLab may serve plain HTTP on the
	// LAN (e.g. the Demo-Lab instance). M3C_GIT_HTTP=1 flips gitlab:// to http://.
	// Production (KuP on-prem) leaves it unset → https. GitHub is always https.
	if os.Getenv("M3C_GIT_HTTP") == "1" {
		remote = "http://" + strings.TrimPrefix(remote, "https://")
	}
	b := newGitBackend(remote, "gitlab")
	b.applyCreds(opts)
	return b, nil
}

// openGitHub maps github://<owner>/<repo>[@ref] → https://github.com/…/….git.
func openGitHub(spec string, opts artifact.OpenOptions) (artifact.Backend, error) {
	rest := strings.SplitN(strings.TrimPrefix(spec, "github://"), "@", 2)[0]
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return nil, fmt.Errorf("git: empty github spec %q", spec)
	}
	b := newGitBackend("https://github.com/"+rest+".git", "github")
	b.applyCreds(opts)
	return b, nil
}

func gitRemoteFromSpec(spec, scheme string) (string, error) {
	rest := strings.SplitN(strings.TrimPrefix(spec, scheme), "@", 2)[0]
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return "", fmt.Errorf("git: empty spec %q", spec)
	}
	return "https://" + rest + ".git", nil
}

// gitBackend is a SPEC-0356 artifact.Backend over a git repository. It is
// stateless: each operation clones into a temp dir, reads/writes the §6
// wire-format, and (for writes) pushes. Correct and simple for v1; a cached
// clone + fetch is the efficiency follow-up.
type gitBackend struct {
	remote    string // clean remote URL (NO secret) — used for Describe/display AND git argv
	scheme    string // "gitlab" | "github"
	token     string // optional write token; supplied to git via an env http.extraHeader ONLY (never argv/URL/.git/config/error strings)
	tokenUser string // "" => "oauth2" (works for a GitLab project/personal access token)
}

func newGitBackend(remote, scheme string) *gitBackend {
	return &gitBackend{remote: remote, scheme: scheme}
}

// applyCreds resolves a token for this backend's host via opts.Creds (read-only,
// SPEC-0356 D5) and stores it for out-of-band header injection (authEnv) — never
// in the URL. Best-effort: no creds / a resolve error just leaves the backend
// anonymous (ambient git credentials or a public repo still work). The token is
// NEVER stored in b.remote and NEVER surfaced by Describe.
func (b *gitBackend) applyCreds(opts artifact.OpenOptions) {
	if opts.Creds == nil {
		return
	}
	host := ""
	if u, err := url.Parse(b.remote); err == nil {
		host = u.Host
	}
	c, err := opts.Creds.Credential(context.Background(), b.scheme, host)
	if err != nil || c.Token == "" {
		return
	}
	b.token = c.Token
	b.tokenUser = c.User
}

// userinfoRe strips credentials embedded in any URL (scheme://user:pass@host).
var userinfoRe = regexp.MustCompile(`://[^/@\s]*@`)

// authUser is the git username for the token (default oauth2, valid for a
// GitLab project/personal access token).
func (b *gitBackend) authUser() string {
	if b.tokenUser != "" {
		return b.tokenUser
	}
	return "oauth2"
}

// authEnv injects the write token as an HTTP Authorization header via git's env
// config — NEVER in the clone/push argv or the on-disk .git/config (SPEC-0356
// §6.2; challenge-gate fix for the token-in-URL / token-in-error leaks). Returns
// nil when anonymous. GIT_CONFIG_* is process-scoped and not persisted; each
// git() call targets a single controlled remote, so an unscoped header is safe.
func (b *gitBackend) authEnv() []string {
	if b.token == "" {
		return nil
	}
	hdr := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(b.authUser()+":"+b.token))
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=" + hdr,
	}
}

// redact strips credential material from a string before it is returned in an
// error: URL userinfo, and the token itself (raw + base64). This closes the
// error-path token leak the challenge gate reproduced.
func (b *gitBackend) redact(s string) string {
	if s == "" {
		return s
	}
	s = userinfoRe.ReplaceAllString(s, "://")
	if b.token != "" {
		s = strings.ReplaceAll(s, b.token, "[REDACTED]")
		enc := base64.StdEncoding.EncodeToString([]byte(b.authUser() + ":" + b.token))
		s = strings.ReplaceAll(s, enc, "[REDACTED]")
	}
	return s
}

// Compile-time assertion.
var _ artifact.Backend = (*gitBackend)(nil)

func (b *gitBackend) Describe() artifact.Descriptor {
	return artifact.Descriptor{
		Scheme:  b.scheme,
		Display: b.scheme + " repo (" + b.remote + ")",
		Capabilities: artifact.Capabilities{
			CanAdmit: true, CanAttest: true, CanRevoke: true,
			ServerEventLog: false, // "the log" is the committed events/ tree
			Paginated:      true,  // git listings are complete
			HonoursSince:   false, // v1: no server-side since filter
			Governance:     artifact.GovFromEventLog,
			LatestPolicy:   artifact.LatestSemverMax,
			Rooms:          false,
			IdentityDir:    false,
			ClaimCheck:     true, // blob committed as a file (LFS in production)
		},
	}
}

func (b *gitBackend) Close() error { return nil }

// --- git exec plumbing ---

func (b *gitBackend) git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=skillctl", "GIT_AUTHOR_EMAIL=skillctl@m3c",
		"GIT_COMMITTER_NAME=skillctl", "GIT_COMMITTER_EMAIL=skillctl@m3c",
	)
	cmd.Env = append(cmd.Env, b.authEnv()...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		red := b.redact(string(out))
		return red, fmt.Errorf("git %s: %w: %s",
			b.redact(strings.Join(args, " ")), err, strings.TrimSpace(red))
	}
	return string(out), nil
}

// withClone clones the remote into a throwaway dir and runs fn against it.
func (b *gitBackend) withClone(fn func(dir string) error) error {
	tmp, err := os.MkdirTemp("", "skillctl-git-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	dir := filepath.Join(tmp, "repo")
	// Clone the CLEAN remote (no token in argv or the resulting .git/config);
	// auth rides in an env http.extraHeader (authEnv).
	if _, err := b.git("", "clone", "--quiet", b.remote, dir); err != nil {
		return err
	}
	return fn(dir)
}

func writeRepoFile(dir, rel string, data []byte) error {
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// --- Publish ---

func (b *gitBackend) Publish(ctx context.Context, req artifact.PublishRequest) (*artifact.PublishResult, error) {
	switch req.Kind {
	case artifact.KindAdmit:
		if len(req.Blob) == 0 {
			return nil, fmt.Errorf("git: %s requires the .skb blob", req.Kind)
		}
	case artifact.KindAttest, artifact.KindRevoke, artifact.KindInstall:
	default:
		return nil, fmt.Errorf("git: unsupported event kind %q", req.Kind)
	}
	name, ver, dig := req.Meta.Name, req.Meta.Version, req.Meta.Digest
	// SEC-M9: these become filesystem paths + git operands — validate BEFORE any use.
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := validateVersion(ver); err != nil {
		return nil, err
	}
	if err := validateDigest(dig); err != nil {
		return nil, err
	}

	var res *artifact.PublishResult
	err := b.withClone(func(dir string) error {
		tag := tagName(name, ver)

		if req.Kind == artifact.KindAdmit {
			if b.tagExists(dir, tag) {
				res = &artifact.PublishResult{
					Ref:           b.ref(name, ver, dig),
					NativeID:      tag,
					Transport:     "git",
					AlreadyExists: true,
				}
				return nil
			}
			if err := writeRepoFile(dir, bundleSkbPath(name, ver), req.Blob); err != nil {
				return err
			}
			bj, err := marshalBundleJSON(bundleJSON{Name: name, Version: ver, Digest: dig, Governance: req.Meta.GovernanceLevel})
			if err != nil {
				return err
			}
			if err := writeRepoFile(dir, bundleJSONPath(name, ver), bj); err != nil {
				return err
			}
		}

		seq := b.nextEventSeq(dir, dig)
		ev, err := marshalEvent(req.Event)
		if err != nil {
			return err
		}
		if err := writeRepoFile(dir, filepath.Join(eventDir(dig), eventFileName(seq, string(req.Kind))), ev); err != nil {
			return err
		}

		if _, err := b.git(dir, "add", "-A"); err != nil {
			return err
		}
		msg := fmt.Sprintf("skill %s@%s (%s) %s", name, ver, req.Kind, dig)
		if _, err := b.git(dir, "commit", "--quiet", "-m", msg); err != nil {
			return err
		}
		if req.Kind == artifact.KindAdmit {
			if _, err := b.git(dir, "tag", "--", tag); err != nil {
				return err
			}
			// Atomic: branch + tag land together or neither does — no
			// half-published skill (blob present, tag missing) on a partial push.
			if _, err := b.git(dir, "push", "--quiet", "--atomic", "origin", "HEAD", "refs/tags/"+tag); err != nil {
				return err
			}
		} else if _, err := b.git(dir, "push", "--quiet", "origin", "HEAD"); err != nil {
			return err
		}
		res = &artifact.PublishResult{Ref: b.ref(name, ver, dig), NativeID: tag, Transport: "git"}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (b *gitBackend) ref(name, ver, dig string) artifact.ArtifactRef {
	return artifact.ArtifactRef{Name: name, Version: ver, Digest: dig, Locator: tagName(name, ver), Scheme: b.scheme}
}

// --- List ---

func (b *gitBackend) List(ctx context.Context, filter artifact.ListFilter, page artifact.Page) (*artifact.Listing, error) {
	var out *artifact.Listing
	err := b.withClone(func(dir string) error {
		skillsDir := filepath.Join(dir, "skills")
		nameEntries, err := os.ReadDir(skillsDir)
		if err != nil {
			if os.IsNotExist(err) {
				out = &artifact.Listing{}
				return nil
			}
			return err
		}
		var skills []artifact.SkillIndexEntry
		for _, ne := range nameEntries {
			if !ne.IsDir() {
				continue
			}
			name := ne.Name()
			if filter.Name != "" && filter.Name != name {
				continue
			}
			rows := b.versionRows(dir, name)
			if len(rows) == 0 {
				continue
			}
			var nonRevoked []string
			for _, r := range rows {
				if r.Status != "revoked" {
					nonRevoked = append(nonRevoked, r.Version)
				}
			}
			latest := maxSemver(nonRevoked)
			if latest == "" {
				latest = maxSemver(versionStrings(rows))
			}
			entry := artifact.SkillIndexEntry{Name: name, IsRevoked: len(nonRevoked) == 0, Versions: rows}
			if r, ok := rowFor(rows, latest); ok {
				entry.LatestVersion = r.Version
				entry.LatestDigest = r.Digest
				entry.LatestGovernance = r.Governance
			}
			if filter.Latest {
				if r, ok := rowFor(rows, latest); ok {
					entry.Versions = []artifact.VersionRow{r}
				}
			}
			skills = append(skills, entry)
		}
		sort.Slice(skills, func(i, j int) bool { return skills[i].Name < skills[j].Name })
		out = &artifact.Listing{Skills: skills} // complete; no cursor
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- Resolve ---

func (b *gitBackend) Resolve(ctx context.Context, q artifact.RefQuery) (*artifact.ArtifactRef, error) {
	var ref *artifact.ArtifactRef
	err := b.withClone(func(dir string) error {
		if q.Digest != "" {
			if err := validateDigest(q.Digest); err != nil {
				return err
			}
		}
		if q.Name != "" {
			if err := validateName(q.Name); err != nil {
				return err
			}
		}
		if q.Version != "" {
			if err := validateVersion(q.Version); err != nil {
				return err
			}
		}
		if q.Name == "" && q.Digest != "" {
			if n, v, dig, ok := b.findByDigest(dir, q.Digest); ok {
				r := b.ref(n, v, dig)
				ref = &r
				return nil
			}
			return fmt.Errorf("git: digest %s not found", q.Digest)
		}
		if q.Name == "" {
			return fmt.Errorf("git: resolve needs a name or a digest")
		}
		ver := q.Version
		if ver == "" {
			var nonRevoked []string
			for _, r := range b.versionRows(dir, q.Name) {
				if r.Status != "revoked" {
					nonRevoked = append(nonRevoked, r.Version)
				}
			}
			ver = maxSemver(nonRevoked)
			if ver == "" {
				return fmt.Errorf("git: no non-revoked version for %s", q.Name)
			}
		}
		bj, err := b.readBundleJSON(dir, q.Name, ver)
		if err != nil {
			return fmt.Errorf("git: %s@%s not found: %w", q.Name, ver, err)
		}
		r := b.ref(q.Name, ver, bj.Digest)
		ref = &r
		return nil
	})
	return ref, err
}

// --- Fetch ---

func (b *gitBackend) Fetch(ctx context.Context, ref artifact.ArtifactRef) ([]byte, error) {
	var data []byte
	err := b.withClone(func(dir string) error {
		name, ver := ref.Name, ref.Version
		if name == "" || ver == "" {
			if err := validateDigest(ref.Digest); err != nil {
				return fmt.Errorf("git: fetch needs name@version or a valid digest: %w", err)
			}
			n, v, _, ok := b.findByDigest(dir, ref.Digest)
			if !ok {
				return fmt.Errorf("git: digest %s not found", ref.Digest)
			}
			name, ver = n, v
		}
		// SEC-M9: a caller-supplied ref must not escape the repo root.
		if err := validateName(name); err != nil {
			return err
		}
		if err := validateVersion(ver); err != nil {
			return err
		}
		d, err := os.ReadFile(filepath.Join(dir, bundleSkbPath(name, ver)))
		if err != nil {
			return fmt.Errorf("git: read blob %s@%s: %w", name, ver, err)
		}
		data = d
		return nil
	})
	return data, err
}

// --- read helpers (operate on a clone's working tree) ---

func (b *gitBackend) tagExists(dir, tag string) bool {
	out, err := b.git(dir, "tag", "-l", tag)
	return err == nil && strings.TrimSpace(out) != ""
}

func (b *gitBackend) nextEventSeq(dir, digest string) int {
	entries, err := os.ReadDir(filepath.Join(dir, eventDir(digest)))
	if err != nil {
		return 1
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n + 1
}

func (b *gitBackend) isRevoked(dir, digest string) bool {
	entries, err := os.ReadDir(filepath.Join(dir, eventDir(digest)))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "-revoked.json") {
			return true
		}
	}
	return false
}

func (b *gitBackend) readBundleJSON(dir, name, ver string) (bundleJSON, error) {
	var bj bundleJSON
	data, err := os.ReadFile(filepath.Join(dir, bundleJSONPath(name, ver)))
	if err != nil {
		return bj, err
	}
	err = json.Unmarshal(data, &bj)
	return bj, err
}

func (b *gitBackend) versionRows(dir, name string) []artifact.VersionRow {
	verEntries, err := os.ReadDir(filepath.Join(dir, "skills", name))
	if err != nil {
		return nil
	}
	var rows []artifact.VersionRow
	for _, ve := range verEntries {
		if !ve.IsDir() {
			continue
		}
		ver := ve.Name()
		bj, err := b.readBundleJSON(dir, name, ver)
		if err != nil {
			continue
		}
		status := "admitted"
		if b.isRevoked(dir, bj.Digest) {
			status = "revoked"
		}
		rows = append(rows, artifact.VersionRow{
			Version: ver, Digest: bj.Digest, Governance: bj.Governance, Status: status,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return semverLess(rows[i].Version, rows[j].Version) })
	return rows
}

func (b *gitBackend) findByDigest(dir, digest string) (name, ver, dig string, ok bool) {
	nameEntries, err := os.ReadDir(filepath.Join(dir, "skills"))
	if err != nil {
		return "", "", "", false
	}
	for _, ne := range nameEntries {
		if !ne.IsDir() {
			continue
		}
		for _, r := range b.versionRows(dir, ne.Name()) {
			if r.Digest == digest {
				return ne.Name(), r.Version, r.Digest, true
			}
		}
	}
	return "", "", "", false
}

func versionStrings(rows []artifact.VersionRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Version)
	}
	return out
}

func rowFor(rows []artifact.VersionRow, version string) (artifact.VersionRow, bool) {
	for _, r := range rows {
		if r.Version == version {
			return r, true
		}
	}
	return artifact.VersionRow{}, false
}
