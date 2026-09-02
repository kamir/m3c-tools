package git

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/netguard"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustcore"
)

// Bounds against a hostile/oversized clone (the git host is untrusted, SPEC-0356
// §6). A malicious repo could commit a multi-GiB bundle.skb or event JSON and OOM
// the pulling host on os.ReadFile. These mirror the OCI backend's ceilings
// (maxBlobBytes / maxManifestBytes) so the two carriers fail closed identically
// (IS-09 / IS-T10).
const (
	maxGitBlobBytes     = 128 << 20 // 128 MiB — the .skb bundle layer (mirror OCI maxBlobBytes)
	maxGitManifestBytes = 4 << 20   // 4 MiB — event JSON + bundle.json (mirror OCI maxManifestBytes)
)

// readCapped reads a regular file from the untrusted clone with a hard byte
// ceiling (IS-T10). It mirrors the OCI backend's fetchCapped bound: reject an
// oversized file BEFORE allocating its contents (the Stat pre-check), and treat
// the LimitReader as the authoritative bound in case Stat lies or the file grows
// mid-read. On oversize it returns a bounded-read ERROR (never a silently
// truncated success), so callers fail closed instead of parsing a partial JSON
// document or a truncated bundle.
func readCapped(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil && fi.Size() > max {
		return nil, fmt.Errorf("git: %s is %d bytes, exceeds cap %d", filepath.Base(p), fi.Size(), max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("git: %s exceeds cap %d bytes", filepath.Base(p), max)
	}
	return data, nil
}

// gitExe resolves the `git` binary ONCE to a validated absolute path. A bare
// exec.Command("git", …) re-runs a PATH lookup on every call, and on Windows a
// `git.exe` dropped in the current working directory (or a writable PATH entry)
// could be executed instead of the real one (the classic cwd/relative-resolution
// hijack). We resolve via exec.LookPath, reject anything that is not an absolute
// path (Go ≥1.19 already refuses a cwd-relative result with exec.ErrDot; the
// IsAbs check makes that guarantee explicit and fail-closed), and cache it.
var (
	gitExeOnce sync.Once
	gitExe     string
	gitExeErr  error
)

func resolveGit() (string, error) {
	gitExeOnce.Do(func() {
		p, err := exec.LookPath("git")
		if err != nil {
			gitExeErr = fmt.Errorf("git: cannot locate a git executable on PATH: %w", err)
			return
		}
		if !filepath.IsAbs(p) {
			gitExeErr = fmt.Errorf("git: refusing to run non-absolute git path %q (possible cwd/relative-resolution hijack)", p)
			return
		}
		gitExe = p
	})
	return gitExe, gitExeErr
}

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
	if err := b.applyCreds(opts); err != nil {
		return nil, err
	}
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
	if err := b.applyCreds(opts); err != nil {
		return nil, err // unreachable in practice (github is always https), kept for uniformity
	}
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
// in the URL. Best-effort for the no-token case: no creds / a resolve error just
// leaves the backend anonymous (ambient git credentials or a public repo still
// work). The token is NEVER stored in b.remote and NEVER surfaced by Describe.
//
// CD-03 / WIN-12 (CD-T8 / WIN-T10): it REFUSES (returns an error) when a resolved
// write token would ride cleartext HTTP to a host that is not provably
// loopback/RFC1918. Base64(user:token) in an Authorization header is encoding,
// not encryption, so an on-path attacker on a public network would capture a
// write-scoped registry token — the same failure class as the OCI plain-HTTP
// guard and ER1_VERIFY_SSL=false. M3C_GIT_HTTP=1 (the only way b.remote becomes
// http://) is for a LAN/test registry; sending a token to a public http:// host
// is never legitimate. HTTPS and loopback/private HTTP are fine. When there is no
// token to attach, cleartext HTTP is left alone (anonymous fetch of a public repo
// over http is the caller's choice, no secret at risk).
func (b *gitBackend) applyCreds(opts artifact.OpenOptions) error {
	if opts.Creds == nil {
		return nil
	}
	host := ""
	if u, err := url.Parse(b.remote); err == nil {
		host = u.Host
	}
	c, err := opts.Creds.Credential(context.Background(), b.scheme, host)
	if err != nil || c.Token == "" {
		return nil // no token → nothing to protect; stay anonymous
	}
	if strings.HasPrefix(b.remote, "http://") && !netguard.IsLoopbackOrPrivate(host) {
		fmt.Fprintf(os.Stderr, "skillctl: SECURITY: REFUSING to attach a %s write token over cleartext HTTP to non-loopback host %q — an on-path attacker would capture it. Use https, or a loopback/RFC1918 registry (M3C_GIT_HTTP is for LAN/test only).\n", b.scheme, host)
		return fmt.Errorf("git: refusing to send credential over plain HTTP to non-loopback host %q; use https or unset M3C_GIT_HTTP", host)
	}
	b.token = c.Token
	b.tokenUser = c.User
	return nil
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

// Compile-time assertions.
var (
	_ artifact.Backend       = (*gitBackend)(nil)
	_ artifact.GovernanceLog = (*gitBackend)(nil)
)

func (b *gitBackend) Describe() artifact.Descriptor {
	return artifact.Descriptor{
		Scheme:  b.scheme,
		Display: b.scheme + " repo (" + b.remote + ")",
		Capabilities: artifact.Capabilities{
			CanAdmit: true, CanAttest: true, CanRevoke: true, CanInstall: true,
			ServerEventLog: true,  // committed events/ tree, surfaced via GovernanceLog.Events
			Paginated:      false, // single-shot: one clone returns the COMPLETE listing; Page.Cursor is not honored
			HonoursSince:   true,  // Events applies ListFilter.Since on occurred_at
			Governance:     artifact.GovFromEventLog,
			LatestPolicy:   artifact.LatestSemverMax,
			Rooms:          false,
			IdentityDir:    false,
			ClaimCheck:     false, // the .skb is committed IN-repo, not stored out-of-line (Git-LFS is a follow-up)
		},
	}
}

func (b *gitBackend) Close() error { return nil }

// --- git exec plumbing ---

func (b *gitBackend) git(dir string, args ...string) (string, error) {
	gitBin, err := resolveGit()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(gitBin, args...)
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
	//
	// core.symlinks=false is a SECURITY control, not a preference: the git host is
	// untrusted (SPEC-0356 §6). With it, git materializes any committed symlink as
	// a regular file holding the link text instead of a real symlink, so a hostile
	// repo cannot commit `.skillctl/registry.json` or `.gitattributes` (or any
	// path) as a symlink that our marker/attribute read+write would follow to
	// escape the clone root. The format.go lstat guards are the belt to this
	// suspenders. Our repos never contain legitimate symlinks.
	if _, err := b.git("", "-c", "core.symlinks=false", "clone", "--quiet", b.remote, dir); err != nil {
		return err
	}
	// SPEC-0356 §6a: refuse a repo whose wire-format version this build cannot
	// understand — BEFORE reading or writing anything (fail closed). Absent
	// marker (fresh/pre-marker repo) is compatible; first publish stamps it.
	if err := checkMarkerCompatible(dir); err != nil {
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

		// Admit is idempotent on the tag: an already-published version is a safe
		// no-op (checked before we stamp anything).
		if req.Kind == artifact.KindAdmit && b.tagExists(dir, tag) {
			res = &artifact.PublishResult{
				Ref:           b.ref(name, ver, dig),
				NativeID:      tag,
				Transport:     "git",
				AlreadyExists: true,
			}
			return nil
		}

		// SPEC-0356 §6a: stamp the write-once version marker + *.skb byte-safety
		// on the first publish into the repo. Idempotent — never rewrites an
		// existing marker. `git add -A` below commits any new format files.
		if _, err := ensureFormatFiles(dir, "skillctl", time.Now()); err != nil {
			return err
		}

		if req.Kind == artifact.KindAdmit {
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
		// The clone is untrusted (SPEC-0356 §6). lstatRegular fails closed on a
		// symlinked blob path so a malicious repo cannot redirect the read outside
		// the clone (defense-in-depth behind the core.symlinks=false clone).
		bp := filepath.Join(dir, bundleSkbPath(name, ver))
		if _, lerr := lstatRegular(bp); lerr != nil {
			return fmt.Errorf("git: read blob %s@%s: %w", name, ver, lerr)
		}
		d, err := readCapped(bp, maxGitBlobBytes)
		if err != nil {
			return fmt.Errorf("git: read blob %s@%s: %w", name, ver, err)
		}
		data = d
		return nil
	})
	return data, err
}

// --- GovernanceLog: surface the raw signed event envelopes for verification ---

// Events implements artifact.GovernanceLog. It returns the RAW signed SPEC-0190
// event envelopes committed under events/<digesthex>/ (admitted/attested/revoked)
// so the SPEC-0188 §7 verifier can re-verify them (envelope sig → digest → author/
// registry sigs → governance floor → revoked). List/Resolve/Fetch read only the
// ADVISORY bundle.json; this is the git backend's trust-read surface. Re-parsing
// the committed pretty-printed JSON round-trips safely: VerifyEnvelopeSignature
// re-canonicalizes from the parsed map, so the on-disk indentation is irrelevant.
func (b *gitBackend) Events(ctx context.Context, filter artifact.ListFilter, page artifact.Page) (*artifact.EventPage, error) {
	var out *artifact.EventPage
	err := b.withClone(func(dir string) error {
		digs, err := b.targetDigestHexes(dir, filter.Name)
		if err != nil {
			return err
		}
		var recs []artifact.EventRecord
		for _, dh := range digs {
			edir := filepath.Join(dir, "events", dh)
			ents, err := os.ReadDir(edir)
			if err != nil {
				continue // no events for this digest yet
			}
			for _, e := range ents {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				// Untrusted clone: skip a symlinked/irregular event file rather than
				// follow it (lstatRegular fails closed on a symlink). A skipped file
				// simply never influences a verdict — the same as a malformed one.
				ep := filepath.Join(edir, e.Name())
				if ok, lerr := lstatRegular(ep); lerr != nil || !ok {
					continue
				}
				data, err := readCapped(ep, maxGitManifestBytes)
				if err != nil {
					continue // oversized/unreadable event → ignore (never influences a verdict)
				}
				var env map[string]any
				if err := json.Unmarshal(data, &env); err != nil {
					continue // a malformed file is untrusted → ignore (never influences a verdict)
				}
				// FR-0090 IS-T1: derive Kind + Digest from the SIGNED envelope, NEVER
				// from the unsigned carrier projection. The file name ("<seq>-<kind>.json")
				// and the events/<digesthex>/ directory are attacker-controllable path
				// projections — a signed revoke of X committed at events/<Yhex>/NNNN-
				// installed.json must surface as {revoke, X}, not {install, Y}, or a
				// hostile registry could relabel a revoke to suppress it or rebind its
				// digest onto an innocent skill. The filename is kept only as NativeID
				// (advisory). See reference_git_event_signed_identity.
				kind := trustcore.KindFromSignedEnvelope(env)
				signedDigest := trustcore.SignedDigest(env)
				if kind == "" || !trustcore.ValidDigest(signedDigest) {
					continue // unclassifiable, or no well-formed signed anchor → drop
				}
				rec := artifact.EventRecord{
					Kind:       kind,
					Digest:     signedDigest,
					Governance: strFromMap(env, "governance_level"),
					Host:       strFromMap(env, "packed_on_host"),
					Rationale:  strFromMap(env, "rationale"),
					NativeID:   e.Name(), // advisory only (the unsigned filename projection)
					Envelope:   env,
				}
				if rec.Host == "" {
					rec.Host = strFromMap(env, "installed_on_host")
				}
				if ts := strFromMap(env, "occurred_at"); ts != "" {
					if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
						rec.OccurredAt = t
					}
				}
				// --since (ListFilter.Since): drop events older than the bound. A
				// zero/unparseable timestamp is kept (best-effort, never a gate).
				if !filter.Since.IsZero() && !rec.OccurredAt.IsZero() && rec.OccurredAt.Before(filter.Since) {
					continue
				}
				recs = append(recs, rec)
			}
		}
		out = &artifact.EventPage{Events: recs}
		return nil
	})
	return out, err
}

// targetDigestHexes returns the events/<digesthex> dir names to scan. With a name
// filter, only the digests of that skill's versions; otherwise every present dir.
func (b *gitBackend) targetDigestHexes(dir, name string) ([]string, error) {
	if name != "" {
		if err := validateName(name); err != nil {
			return nil, err
		}
		var out []string
		for _, r := range b.versionRows(dir, name) {
			out = append(out, digestHex(r.Digest))
		}
		return out, nil
	}
	ents, err := os.ReadDir(filepath.Join(dir, "events"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// kindFromEventFile (the old filename-projection classifier) was removed in
// FR-0090 IS-T1: Events() now classifies from the SIGNED envelope via
// trustcore.KindFromSignedEnvelope, and the "<seq>-<kind>.json" name is advisory
// (NativeID) only. isRevoked() below still reads the filename, but purely for the
// List/Resolve DISPLAY status column — never for a trust decision (parity with the
// OCI backend's advisory digestRevoked; the authoritative revoke gate is the pull
// gauntlet's signed-envelope path).

func strFromMap(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
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
	// Untrusted clone: fail closed on a symlinked manifest path (see lstatRegular).
	mp := filepath.Join(dir, bundleJSONPath(name, ver))
	if _, lerr := lstatRegular(mp); lerr != nil {
		return bj, lerr
	}
	data, err := readCapped(mp, maxGitManifestBytes)
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
