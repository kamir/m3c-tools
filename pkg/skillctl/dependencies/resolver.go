package dependencies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// Artifact carries declarations from the exact digest-authenticated manifest.
// Authority identifies the consumer-selected trust namespace. The resolver cannot
// establish authenticity from these fields; the source must verify each candidate.
type Artifact struct {
	Authority    string                   `json:"authority"`
	Kind         string                   `json:"kind"`
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	Digest       string                   `json:"digest"`
	Declarations []skillbundle.Dependency `json:"declarations"`
}

// ArtifactSource returns authenticated candidates, not mutable registry projections.
// Network/cache authorization and trust verification remain the consumer's job.
type ArtifactSource interface {
	Candidates(context.Context, string, string) ([]Artifact, error)
}

// Observation binds a selected executable and the observed runtime evidence.
type Observation struct {
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	Path             string `json:"path"`
	ExecutableDigest string `json:"executable_digest"`
	EvidenceDigest   string `json:"evidence_digest"`
}

// Report is a deterministic observation lock, not an author-signed lockfile.
type Report struct {
	Schema           string        `json:"schema"`
	ConstraintPolicy string        `json:"constraint_policy"`
	ProfileDigest    string        `json:"profile_digest"`
	Platform         string        `json:"platform"`
	Root             Artifact      `json:"root"`
	Artifacts        []Artifact    `json:"artifacts"`
	Runtime          []Observation `json:"runtime"`
	LockDigest       string        `json:"lock_digest"`
	Complete         bool          `json:"complete"`
}

// Resolver snapshots a validated profile. It never searches PATH or provisions.
type Resolver struct {
	profile Profile
	source  ArtifactSource
}

func NewResolver(p Profile, s ArtifactSource) (*Resolver, error) {
	if p.Schema == "" && p.ProjectRoot == "" && p.Python == nil && len(p.Tools) == 0 {
		return &Resolver{source: s}, nil
	}
	if validateProfile(p) != nil {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(p)
	if e != nil {
		return nil, ErrInvalid
	}
	copy, e := ParseProfile(b)
	if e != nil {
		return nil, e
	}
	return &Resolver{profile: copy, source: s}, nil
}

const (
	maxCatalogPools        = 256
	maxCatalogCandidates   = 4096
	maxCatalogDeclarations = 16384
	maxCatalogFieldBytes   = 4 << 20
)

// Catalog budgets include the root and every provider candidate, including
// duplicate candidates and abandoned backtracking branches. They bound resolver
// copies, not allocations already made by an external ArtifactSource.
var errCatalogBudget = fmt.Errorf("artifact catalog budget exhausted: %w", ErrUnresolved)

type catalogBudget struct {
	pools, candidates, declarations, fieldBytes int
}

func (b *catalogBudget) reservePool() error {
	if b.pools >= maxCatalogPools {
		return errCatalogBudget
	}
	b.pools++
	return nil
}

// reserveArtifact checks aggregate limits before copying or serializing fields.
func (b *catalogBudget) reserveArtifact(a Artifact) error {
	if b.candidates >= maxCatalogCandidates || len(a.Declarations) > maxCatalogDeclarations-b.declarations {
		return errCatalogBudget
	}
	addField := func(value string) error {
		if len(value) > maxCatalogFieldBytes-b.fieldBytes {
			return errCatalogBudget
		}
		if !utf8.ValidString(value) {
			return ErrInvalid
		}
		b.fieldBytes += len(value)
		return nil
	}
	for _, field := range []string{a.Authority, a.Kind, a.Name, a.Version, a.Digest} {
		if err := addField(field); err != nil {
			return err
		}
	}
	for _, declaration := range a.Declarations {
		for _, field := range []string{declaration.Kind, declaration.Name, declaration.Constraint} {
			if err := addField(field); err != nil {
				return err
			}
		}
	}
	b.candidates++
	b.declarations += len(a.Declarations)
	return nil
}

func validateArtifact(a Artifact) error {
	if (a.Kind != "skill" && a.Kind != "agent") || !validName(a.Name) || a.Authority == "" || len(a.Authority) > 512 {
		return ErrInvalid
	}
	if _, e := release(a.Version); e != nil {
		return e
	}
	if _, e := canonicalDigest(a.Digest); e != nil {
		return e
	}
	if len(a.Declarations) > 256 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, d := range a.Declarations {
		if !validName(d.Name) || len(d.Constraint) > 512 {
			return ErrInvalid
		}
		identity := d.Name
		if d.Kind == "python" {
			identity = pythonName(identity)
		}
		key := d.Kind + ":" + identity
		if seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		switch d.Kind {
		case "python":
		case "skill", "agent", "system":
			if _, e := matchRelease("0", d.Constraint); e != nil {
				return e
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}
func cloneArtifact(a Artifact) Artifact {
	a.Declarations = append([]skillbundle.Dependency{}, a.Declarations...)
	for i := range a.Declarations {
		if a.Declarations[i].Kind == "python" {
			a.Declarations[i].Name = pythonName(a.Declarations[i].Name)
		}
	}
	sort.Slice(a.Declarations, func(i, j int) bool {
		a, b := a.Declarations[i], a.Declarations[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	a.Digest, _ = canonicalDigest(a.Digest)
	return a
}

// Resolve resolves the entire declared graph without installing or writing state.
// Compatible versions are tried highest first with bounded graph backtracking.
// A failure returns no complete lock. All candidates must belong to the root's
// explicit namespace. Cross-namespace resolution needs a future explicit contract.
func (r *Resolver) Resolve(ctx context.Context, root Artifact) (*Report, error) {
	budget := catalogBudget{}
	if e := budget.reserveArtifact(root); e != nil {
		return nil, e
	}
	if e := validateArtifact(root); e != nil {
		return nil, e
	}
	root = cloneArtifact(root)
	pb, _ := json.Marshal(r.profile)
	out := &Report{Schema: "m3c.skillctl.runtime-lock/v1", ConstraintPolicy: ReleaseConstraintPolicy, ProfileDigest: digest(pb), Platform: runtime.GOOS + "/" + runtime.GOARCH, Root: root, Artifacts: []Artifact{}, Runtime: []Observation{}}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	assigned := map[string]Artifact{root.Kind + ":" + root.Name: root}
	pending := append([]skillbundle.Dependency{}, root.Declarations...)
	pools := map[string][]Artifact{}
	attempts := 0
	var solve func(map[string]Artifact, []skillbundle.Dependency) (map[string]Artifact, []Observation, error)
	solve = func(chosen map[string]Artifact, remaining []skillbundle.Dependency) (map[string]Artifact, []Observation, error) {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		attempts++
		if attempts > 4096 || len(chosen) > 256 || len(remaining) > 1024 {
			return nil, nil, ErrUnresolved
		}
		if len(remaining) == 0 {
			if e := checkGraph(chosen, root); e != nil {
				return nil, nil, e
			}
			var python, system []skillbundle.Dependency
			keys := make([]string, 0, len(chosen))
			for k := range chosen {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				for _, d := range chosen[k].Declarations {
					switch d.Kind {
					case "python":
						python = append(python, d)
					case "system":
						system = append(system, d)
					}
				}
			}
			tools, e := r.checkTools(ctx, system)
			if e != nil {
				return nil, nil, e
			}
			py, e := r.checkPython(ctx, python)
			if e != nil {
				return nil, nil, e
			}
			return chosen, append(tools, py...), nil
		}
		requirement := remaining[0]
		remaining = remaining[1:]
		if requirement.Kind == "python" || requirement.Kind == "system" {
			return solve(chosen, remaining)
		}
		key := requirement.Kind + ":" + requirement.Name
		if existing, ok := chosen[key]; ok {
			matches, e := matchRelease(existing.Version, requirement.Constraint)
			if e != nil {
				return nil, nil, e
			}
			if !matches {
				return nil, nil, ErrUnresolved
			}
			return solve(chosen, remaining)
		}
		candidates, loaded := pools[key]
		if !loaded {
			if r.source == nil {
				return nil, nil, ErrUnresolved
			}
			if e := budget.reservePool(); e != nil {
				return nil, nil, e
			}
			raw, e := r.source.Candidates(ctx, requirement.Kind, requirement.Name)
			if e != nil {
				if ctx.Err() != nil {
					return nil, nil, ctx.Err()
				}
				return nil, nil, fmt.Errorf("artifact source unavailable: %w", ErrUnresolved)
			}
			if len(raw) > 256 || len(raw) > maxCatalogCandidates-budget.candidates {
				return nil, nil, errCatalogBudget
			}
			versions := map[[4]uint64]Artifact{}
			for _, candidate := range raw {
				if e := budget.reserveArtifact(candidate); e != nil {
					return nil, nil, e
				}
				if validateArtifact(candidate) != nil || candidate.Kind != requirement.Kind || candidate.Name != requirement.Name || candidate.Authority != root.Authority {
					return nil, nil, ErrInvalid
				}
				candidate = cloneArtifact(candidate)
				version, _ := release(candidate.Version)
				if previous, ok := versions[version]; ok {
					if !sameArtifact(previous, candidate) {
						return nil, nil, fmt.Errorf("artifact version ambiguous: %w", ErrInvalid)
					}
					continue
				}
				versions[version] = candidate
				candidates = append(candidates, candidate)
			}
			sort.Slice(candidates, func(i, j int) bool {
				a, _ := release(candidates[i].Version)
				b, _ := release(candidates[j].Version)
				return compare(a, b) > 0
			})
			pools[key] = candidates
		}
		for _, candidate := range candidates {
			matches, e := matchRelease(candidate.Version, requirement.Constraint)
			if e != nil {
				return nil, nil, e
			}
			if !matches {
				continue
			}
			next := make(map[string]Artifact, len(chosen)+1)
			for k, v := range chosen {
				next[k] = v
			}
			next[key] = candidate
			todo := make([]skillbundle.Dependency, 0, len(remaining)+len(candidate.Declarations))
			todo = append(todo, candidate.Declarations...)
			todo = append(todo, remaining...)
			result, observations, e := solve(next, todo)
			if e == nil {
				return result, observations, nil
			}
			if errors.Is(e, errCatalogBudget) || !errors.Is(e, ErrUnresolved) {
				return nil, nil, e
			}
		}
		return nil, nil, ErrUnresolved
	}
	selected, observations, e := solve(assigned, pending)
	if e != nil {
		return nil, e
	}
	for k, a := range selected {
		if k != root.Kind+":"+root.Name {
			out.Artifacts = append(out.Artifacts, a)
		}
	}
	sort.Slice(out.Artifacts, func(i, j int) bool {
		a, b := out.Artifacts[i], out.Artifacts[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	out.Runtime = observations
	sort.Slice(out.Runtime, func(i, j int) bool {
		a, b := out.Runtime[i], out.Runtime[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	out.Complete = true
	b, e := json.Marshal(out)
	if e != nil {
		return nil, ErrInvalid
	}
	out.LockDigest = digest(b)
	return out, nil
}

// Recheck repeats resolution and all runtime probes immediately before the
// consumer's commit. It does not hold an OS lock on runtimes or promise that an
// external process cannot change them after this call returns.
func (r *Resolver) Recheck(ctx context.Context, root Artifact, expectedLockDigest string) (*Report, error) {
	want, e := canonicalDigest(expectedLockDigest)
	if e != nil {
		return nil, e
	}
	out, e := r.Resolve(ctx, root)
	if e != nil {
		return nil, e
	}
	if out.LockDigest != want {
		return nil, ErrDrift
	}
	return out, nil
}

func sameArtifact(a, b Artifact) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func checkGraph(chosen map[string]Artifact, root Artifact) error {
	active := map[string]bool{}
	heights := map[string]int{}
	var visit func(string) (int, error)
	visit = func(key string) (int, error) {
		if active[key] {
			return 0, ErrUnresolved
		}
		if height, ok := heights[key]; ok {
			return height, nil
		}
		active[key] = true
		height := 0
		for _, d := range chosen[key].Declarations {
			if d.Kind == "skill" || d.Kind == "agent" {
				child, e := visit(d.Kind + ":" + d.Name)
				if e != nil {
					return 0, e
				}
				if child+1 > height {
					height = child + 1
				}
			}
		}
		delete(active, key)
		if height > 32 {
			return 0, ErrUnresolved
		}
		heights[key] = height
		return height, nil
	}
	_, e := visit(root.Kind + ":" + root.Name)
	return e
}

var pythonSeparators = regexp.MustCompile(`[-_.]+`)

func pythonName(s string) string { return pythonSeparators.ReplaceAllString(strings.ToLower(s), "-") }
