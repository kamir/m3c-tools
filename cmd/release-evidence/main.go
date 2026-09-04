// Command release-evidence assembles the Release Evidence Bundle (the "Trust
// Binder") for an m3c-tools / skillctl release: H10 of the WF-001 hardening
// track.
//
// It answers ONE question in machine-readable, signable form: did this exact set
// of release artifacts come from commit X AND pass the mandatory gate-set G at
// time T? It is an INDEX of evidence, not a second copy of it: the bundle POINTS
// at the already-produced cosign bundle / SLSA provenance / SBOM by URL (+digest)
// rather than re-embedding or re-verifying them, which keeps the SLSA L3 build
// isolation intact (assembly runs in a no-signing job; only a downstream cosign
// step signs the assembled bundle).
//
// Design decision H10d:
//   - agent (not human) schema; in-toto + cosign-keyless framing;
//   - `summary.enterprise_ready` is RECOMPUTED here from the gate results under a
//     fixed policy G, never taken on trust from an input. A strict CONSUMER is
//     expected to recompute it again against its own policy; this tool's job is to
//     compute the honest value and make the inputs auditable.
//
// The `required` set (gate-set G) is POLICY and lives in the registry below. It
// is NOT caller-overridable. A caller supplies only each gate's STATUS (+ optional
// evidence URL / note). This is deliberate: it prevents a caller from marking a
// required gate `required:false` to fake enterprise-readiness.
//
// Zero external dependencies (stdlib only), matching the repo's zero-dep core.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	toolName      = "release-evidence"
	toolVersion   = "0.1.0"
	schemaVersion = "0.1.0"
	predicateType = "https://m3c-tools.dev/attestations/release-evidence/v0"
	intotoType    = "https://in-toto.io/Statement/v1"
	policyID      = "trust-binder/policy@v0"
	policyRule    = "enterprise_ready = every REQUIRED gate (set G) has status==pass; " +
		"a required gate that is fail OR skip => not ready. Advisory gates (required:false) " +
		"never block. The required set is fixed by policy, not by the caller. A strict " +
		"verifier RECOMPUTES this from `gates` under its own policy rather than trusting the bool."
)

// gateMeta is the FIXED, policy-owned metadata for a gate. Only `status` (and
// optional evidence/note) come from the caller; everything here is baked in so
// the gate-set G and its required-ness cannot be forged through inputs.
type gateMeta struct {
	id            string
	name          string
	kind          string
	required      bool
	verifiability string
	evidenceType  string
}

// registry is the mandatory gate-set G (H10d). Order is presentational and
// mirrors the H10p prototype. The `required` column IS policy G:
//
//	12 required (the now-real gates) + threat-model-delta advisory.
//
// If a gate id here drifts from the shipped JSON-schema enum, the -schema
// cross-check fails the build (keeps schema and policy in lockstep).
var registry = []gateMeta{
	{"unit-tests", "Unit Tests", "test", true, "trust-ci", "ci-log"},
	{"race", "skillctl Security Tests (-race)", "test", true, "trust-ci", "ci-log"},
	{"e2e", "e2e tests (allow-list)", "test", true, "trust-ci", "ci-log"},
	{"lint", "Lint & Vet", "test", true, "trust-ci", "ci-log"},
	{"gosec-sast", "gosec SAST", "sast", true, "trust-ci", "ci-log"},
	{"govulncheck-cve", "govulncheck (reachable CVEs)", "sca", true, "trust-ci", "ci-log"},
	{"gitleaks-secret", "gitleaks (secret scan)", "secret", true, "trust-ci", "ci-log"},
	{"sbom", "CycloneDX SBOM", "sbom", true, "re-verify", "release-asset"},
	{"docaudit", "skillctl CLI/manual consistency (docaudit)", "docs", true, "trust-ci", "ci-log"},
	{"slsa-provenance", "SLSA L3 provenance + slsa-verifier gate", "provenance", true, "re-verify", "attestation"},
	{"cosign-signature", "cosign sign-blob SHA256SUMS (keyless OIDC)", "signature", true, "re-verify", "attestation"},
	{"platform-smoke", "Per-platform runtime smoke of the signed binary", "smoke", true, "trust-ci", "ci-log"},
	{"threat-model-delta", "Threat-model / security-triad delta", "threat-model", false, "reference", "external"},
}

func registryByID() map[string]gateMeta {
	m := make(map[string]gateMeta, len(registry))
	for _, g := range registry {
		m[g.id] = g
	}
	return m
}

// ---- schema structs (JSON field order = output order) -----------------------

type Bundle struct {
	SchemaVersion string       `json:"schema_version"`
	PredicateType string       `json:"predicate_type,omitempty"`
	BundleID      string       `json:"bundle_id,omitempty"`
	Subject       Subject      `json:"subject"`
	ProducedAt    string       `json:"produced_at"`
	GeneratedBy   *GeneratedBy `json:"generated_by,omitempty"`
	Policy        *Policy      `json:"policy,omitempty"`
	Gates         []Gate       `json:"gates"`
	References    []Reference  `json:"references,omitempty"`
	Summary       Summary      `json:"summary"`
}

type Subject struct {
	Repo            string     `json:"repo"`
	SourceURI       string     `json:"source_uri,omitempty"`
	Commit          string     `json:"commit"`
	Tag             string     `json:"tag"`
	Channel         string     `json:"channel,omitempty"`
	ArtifactDigests []Artifact `json:"artifact_digests"`
}

type Artifact struct {
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

type Digest struct {
	SHA256 string `json:"sha256"`
}

type GeneratedBy struct {
	Tool        string `json:"tool,omitempty"`
	Version     string `json:"version,omitempty"`
	WorkflowRun string `json:"workflow_run,omitempty"`
}

type Policy struct {
	ID   string `json:"id"`
	Rule string `json:"rule,omitempty"`
}

type Gate struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Required      bool   `json:"required"`
	EvidenceRef   string `json:"evidence_ref,omitempty"`
	EvidenceType  string `json:"evidence_type,omitempty"`
	Verifiability string `json:"verifiability,omitempty"`
	Note          string `json:"note,omitempty"`
}

type Reference struct {
	Type   string `json:"type"`
	URI    string `json:"uri"`
	SHA256 string `json:"sha256,omitempty"`
}

type Summary struct {
	RequiredTotal   int      `json:"required_total"`
	RequiredPassed  int      `json:"required_passed"`
	RequiredFailed  int      `json:"required_failed"`
	Skipped         int      `json:"skipped"`
	EnterpriseReady bool     `json:"enterprise_ready"`
	Caveats         []string `json:"caveats,omitempty"`
}

// Statement is the in-toto v1 wrapper: subject = the artifact digests, predicate
// = the Bundle. Cheap framing so the bundle can be attached as an attestation
// tied to the same subjects as the SLSA provenance.
type Statement struct {
	Type          string     `json:"_type"`
	Subject       []Artifact `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     *Bundle    `json:"predicate"`
}

// ---- caller-supplied gate result --------------------------------------------

type gateInput struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Evidence string `json:"evidence,omitempty"`
	Note     string `json:"note,omitempty"`
}

// ---- options (buildBundle input; keeps main() thin + the logic testable) -----

type options struct {
	commit, tag, repo, runURL string
	channel                   string
	sourceURI                 string
	provenanceName            string
	sbomName                  string
	checksumsSHA256           string
	producedAt                string
	toolVersion               string
	artifacts                 []Artifact
	gates                     []gateInput
	extraRefs                 []Reference
	autoRefs                  bool
}

var (
	reSHA1     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reSemver   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reRepo     = regexp.MustCompile(`^[^/\s]+/[^/\s]+$`)
	validStat  = map[string]bool{"pass": true, "fail": true, "skip": true}
	validKind  = map[string]bool{"test": true, "sast": true, "sca": true, "secret": true, "provenance": true, "signature": true, "sbom": true, "docs": true, "smoke": true, "threat-model": true}
	validRefTy = map[string]bool{"checksums": true, "cosign-bundle": true, "slsa-provenance": true, "sbom": true, "ed25519-sig": true, "pubkey": true}
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)

	var (
		commit    = fs.String("commit", "", "full 40-hex release commit SHA (required)")
		tag       = fs.String("tag", "", "release tag, e.g. skillctl/v0.5.0 (required)")
		repo      = fs.String("repo", "", "owner/name, e.g. kamir/m3c-tools (required)")
		runURL    = fs.String("run-url", "", "URL of the CI run assembling this bundle")
		channel   = fs.String("channel", "skillctl", "release channel: product|skillctl")
		out       = fs.String("out", "release-evidence.json", "output path for the bundle JSON")
		intoto    = fs.String("intoto", "", "if set, also write an in-toto Statement wrapping the bundle to this path")
		sourceURI = fs.String("source-uri", "", "git+https source URI (default git+https://github.com/<repo>)")
		schemaP   = fs.String("schema", "docs/security/release-evidence.schema.json", "JSON-schema to cross-check the gate-id enum against (soft-skip if absent)")
		provName  = fs.String("provenance-name", "multiple.intoto.jsonl", "SLSA provenance asset filename (for evidence + references)")
		sbomName  = fs.String("sbom-name", "skillctl.sbom.cdx.json", "SBOM asset filename (for evidence + references)")
		sumsSHA   = fs.String("checksums-sha256", "", "sha256 of SHA256SUMS, for the checksums reference (tamper-evident pointer)")
		producedA = fs.String("produced-at", "", "RFC3339 assembly time (default: now, UTC)")
		toolVer   = fs.String("tool-version", toolVersion, "version stamped into generated_by")
		artFile   = fs.String("artifacts", "", "path to a SHA256SUMS file to parse into subject.artifact_digests")
		gatesFile = fs.String("gates-file", "", "path to a JSON array of {id,status,evidence,note} gate results")
		noRefs    = fs.Bool("no-auto-refs", false, "do not auto-build the standard references[] index")
	)
	var gateFlags multiFlag
	var artFlags multiFlag
	var refFlags multiFlag
	fs.Var(&gateFlags, "gate", "repeatable: id=status[,evidence=url][,note=text] (status accepts GitHub needs.*.result too)")
	fs.Var(&artFlags, "artifact", "repeatable: name=<sha256> (alternative/supplement to -artifacts)")
	fs.Var(&refFlags, "reference", "repeatable extra reference: type=uri[,sha256=hex]")

	if err := fs.Parse(argv); err != nil {
		return 2
	}

	opts := options{
		commit:          strings.TrimSpace(*commit),
		tag:             strings.TrimSpace(*tag),
		repo:            strings.TrimSpace(*repo),
		runURL:          strings.TrimSpace(*runURL),
		channel:         strings.TrimSpace(*channel),
		sourceURI:       strings.TrimSpace(*sourceURI),
		provenanceName:  strings.TrimSpace(*provName),
		sbomName:        strings.TrimSpace(*sbomName),
		checksumsSHA256: strings.TrimSpace(*sumsSHA),
		producedAt:      strings.TrimSpace(*producedA),
		toolVersion:     strings.TrimSpace(*toolVer),
		autoRefs:        !*noRefs,
	}

	// Gate results: file first, then -gate flags (flags win on duplicate id).
	var gerr error
	if *gatesFile != "" {
		opts.gates, gerr = loadGatesFile(*gatesFile)
		if gerr != nil {
			fmt.Fprintf(os.Stderr, "release-evidence: %v\n", gerr)
			return 1
		}
	}
	for _, g := range gateFlags {
		gi, err := parseGateFlag(g)
		if err != nil {
			fmt.Fprintf(os.Stderr, "release-evidence: -gate %q: %v\n", g, err)
			return 1
		}
		opts.gates = upsertGate(opts.gates, gi)
	}

	// Artifact digests: SHA256SUMS file first, then -artifact flags.
	if *artFile != "" {
		arts, err := parseChecksums(*artFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "release-evidence: -artifacts %q: %v\n", *artFile, err)
			return 1
		}
		opts.artifacts = append(opts.artifacts, arts...)
	}
	for _, a := range artFlags {
		art, err := parseArtifactFlag(a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "release-evidence: -artifact %q: %v\n", a, err)
			return 1
		}
		opts.artifacts = append(opts.artifacts, art)
	}
	for _, r := range refFlags {
		ref, err := parseReferenceFlag(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "release-evidence: -reference %q: %v\n", r, err)
			return 1
		}
		opts.extraRefs = append(opts.extraRefs, ref)
	}

	// Cross-check the shipped schema's gate-id enum against the registry, so the
	// policy set G and the schema never silently drift. Soft-skip if absent.
	if err := crossCheckSchema(*schemaP); err != nil {
		fmt.Fprintf(os.Stderr, "release-evidence: schema cross-check: %v\n", err)
		return 1
	}

	b, err := buildBundle(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-evidence: %v\n", err)
		return 1
	}
	if err := validate(b); err != nil {
		fmt.Fprintf(os.Stderr, "release-evidence: invalid bundle: %v\n", err)
		return 1
	}

	if err := writeJSON(*out, b); err != nil {
		fmt.Fprintf(os.Stderr, "release-evidence: write %q: %v\n", *out, err)
		return 1
	}
	if *intoto != "" {
		st := &Statement{Type: intotoType, Subject: b.Subject.ArtifactDigests, PredicateType: predicateType, Predicate: b}
		if err := writeJSON(*intoto, st); err != nil {
			fmt.Fprintf(os.Stderr, "release-evidence: write %q: %v\n", *intoto, err)
			return 1
		}
	}

	fmt.Fprintf(os.Stderr,
		"release-evidence: %s: enterprise_ready=%v (required %d/%d pass, %d skipped) -> %s\n",
		b.BundleID, b.Summary.EnterpriseReady, b.Summary.RequiredPassed, b.Summary.RequiredTotal, b.Summary.Skipped, *out)
	return 0
}

// buildBundle assembles the bundle from options. It ALWAYS emits one gate per
// registry entry (a gate with no supplied result is recorded as skip with a
// note), so the gate-set G is complete and enterprise_ready is honest.
func buildBundle(o options) (*Bundle, error) {
	if o.commit == "" || o.tag == "" || o.repo == "" {
		return nil, errors.New("-commit, -tag and -repo are all required")
	}
	if o.channel == "" {
		o.channel = "skillctl"
	}
	if o.sourceURI == "" {
		o.sourceURI = "git+https://github.com/" + o.repo
	}
	if o.producedAt == "" {
		o.producedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if o.toolVersion == "" {
		o.toolVersion = toolVersion
	}

	base := "https://github.com/" + o.repo + "/releases/download/" + o.tag

	// index caller results by id (normalising status).
	supplied := make(map[string]gateInput, len(o.gates))
	for _, g := range o.gates {
		id := strings.TrimSpace(g.ID)
		st, err := normalizeStatus(g.Status)
		if err != nil {
			return nil, fmt.Errorf("gate %q: %w", id, err)
		}
		g.ID, g.Status = id, st
		supplied[id] = g
	}
	// reject results for unknown gate ids (typo / drift protection).
	known := registryByID()
	for id := range supplied {
		if _, ok := known[id]; !ok {
			return nil, fmt.Errorf("gate %q is not in the policy gate-set G", id)
		}
	}

	gates := make([]Gate, 0, len(registry))
	for _, m := range registry {
		g := Gate{
			ID: m.id, Name: m.name, Kind: m.kind, Required: m.required,
			EvidenceType: m.evidenceType, Verifiability: m.verifiability,
		}
		if in, ok := supplied[m.id]; ok {
			g.Status = in.Status
			g.EvidenceRef = strings.TrimSpace(in.Evidence)
			g.Note = strings.TrimSpace(in.Note)
		} else {
			g.Status = "skip"
			g.Note = "no gate result supplied at assembly time"
		}
		if g.EvidenceRef == "" {
			g.EvidenceRef = defaultEvidence(m, base, o)
		}
		gates = append(gates, g)
	}

	b := &Bundle{
		SchemaVersion: schemaVersion,
		PredicateType: predicateType,
		BundleID:      o.repo + "@" + o.tag,
		Subject: Subject{
			Repo:            o.repo,
			SourceURI:       o.sourceURI,
			Commit:          o.commit,
			Tag:             o.tag,
			Channel:         o.channel,
			ArtifactDigests: o.artifacts,
		},
		ProducedAt:  o.producedAt,
		GeneratedBy: &GeneratedBy{Tool: toolName, Version: o.toolVersion, WorkflowRun: o.runURL},
		Policy:      &Policy{ID: policyID, Rule: policyRule},
		Gates:       gates,
		References:  buildReferences(o, base),
		Summary:     computeSummary(gates),
	}
	return b, nil
}

// defaultEvidence supplies a sensible evidence_ref when the caller gave none:
// asset-backed (re-verify) gates point at their release asset; everything else
// points at the assembling run.
func defaultEvidence(m gateMeta, base string, o options) string {
	switch m.id {
	case "sbom":
		return base + "/" + o.sbomName
	case "slsa-provenance":
		return base + "/" + o.provenanceName
	case "cosign-signature":
		return base + "/SHA256SUMS.cosign.bundle"
	default:
		return o.runURL
	}
}

// buildReferences emits the evidence INDEX: pointers (not copies) at the
// aggregate artifacts a verifier can fetch + re-verify. For the skillctl channel
// this is the standard six-asset set; extra/override refs are appended.
func buildReferences(o options, base string) []Reference {
	var refs []Reference
	if o.autoRefs && o.channel == "skillctl" {
		refs = append(refs,
			Reference{Type: "checksums", URI: base + "/SHA256SUMS", SHA256: o.checksumsSHA256},
			Reference{Type: "cosign-bundle", URI: base + "/SHA256SUMS.cosign.bundle"},
			Reference{Type: "slsa-provenance", URI: base + "/" + o.provenanceName},
			Reference{Type: "sbom", URI: base + "/" + o.sbomName},
			Reference{Type: "ed25519-sig", URI: base + "/SHA256SUMS.sig"},
			Reference{Type: "pubkey", URI: base + "/skillctl-release.pub"},
		)
	}
	return append(refs, o.extraRefs...)
}

// computeSummary RECOMPUTES enterprise_ready from the gate results under policy G.
// This is the trust-bearing function: the stored bool is derived here, never
// taken from an input.
func computeSummary(gates []Gate) Summary {
	var s Summary
	var caveats []string
	for _, g := range gates {
		if g.Status == "skip" {
			s.Skipped++
		}
		if g.Required {
			s.RequiredTotal++
			switch g.Status {
			case "pass":
				s.RequiredPassed++
			case "fail":
				s.RequiredFailed++
			}
		} else if g.Status != "pass" {
			caveats = append(caveats, fmt.Sprintf("%s (%s, advisory): not counted toward enterprise_ready.", g.ID, g.Status))
		}
	}
	// enterprise_ready: no required failure AND every required gate passed (a
	// required skip lands in neither passed nor failed, so it fails this test).
	s.EnterpriseReady = s.RequiredFailed == 0 && s.RequiredPassed == s.RequiredTotal
	s.Caveats = caveats
	return s
}

// validate re-checks the assembled bundle against the schema's load-bearing
// constraints (stdlib-only structural validation) and confirms the stored
// summary matches an independent recompute.
func validate(b *Bundle) error {
	if !reSemver.MatchString(b.SchemaVersion) {
		return fmt.Errorf("schema_version %q is not semver", b.SchemaVersion)
	}
	if !reRepo.MatchString(b.Subject.Repo) {
		return fmt.Errorf("subject.repo %q must be owner/name", b.Subject.Repo)
	}
	if !reSHA1.MatchString(b.Subject.Commit) {
		return fmt.Errorf("subject.commit %q must be a 40-hex sha", b.Subject.Commit)
	}
	if strings.TrimSpace(b.Subject.Tag) == "" {
		return errors.New("subject.tag is empty")
	}
	if b.Subject.Channel != "" && b.Subject.Channel != "product" && b.Subject.Channel != "skillctl" {
		return fmt.Errorf("subject.channel %q must be product|skillctl", b.Subject.Channel)
	}
	if len(b.Subject.ArtifactDigests) < 1 {
		return errors.New("subject.artifact_digests must have at least one entry")
	}
	for _, a := range b.Subject.ArtifactDigests {
		if strings.TrimSpace(a.Name) == "" {
			return errors.New("artifact_digests: empty name")
		}
		if !reSHA256.MatchString(a.Digest.SHA256) {
			return fmt.Errorf("artifact %q: digest.sha256 %q must be 64-hex", a.Name, a.Digest.SHA256)
		}
	}
	if strings.TrimSpace(b.ProducedAt) == "" {
		return errors.New("produced_at is empty")
	}
	if _, err := time.Parse(time.RFC3339, b.ProducedAt); err != nil {
		return fmt.Errorf("produced_at %q is not RFC3339: %w", b.ProducedAt, err)
	}
	known := registryByID()
	seen := map[string]bool{}
	for _, g := range b.Gates {
		if _, ok := known[g.ID]; !ok {
			return fmt.Errorf("gate id %q not in enum", g.ID)
		}
		if seen[g.ID] {
			return fmt.Errorf("duplicate gate id %q", g.ID)
		}
		seen[g.ID] = true
		if !validStat[g.Status] {
			return fmt.Errorf("gate %q: status %q must be pass|fail|skip", g.ID, g.Status)
		}
		if !validKind[g.Kind] {
			return fmt.Errorf("gate %q: kind %q invalid", g.ID, g.Kind)
		}
	}
	for _, r := range b.References {
		if !validRefTy[r.Type] {
			return fmt.Errorf("reference type %q invalid", r.Type)
		}
		if strings.TrimSpace(r.URI) == "" {
			return fmt.Errorf("reference %q: empty uri", r.Type)
		}
		if r.SHA256 != "" && !reSHA256.MatchString(r.SHA256) {
			return fmt.Errorf("reference %q: sha256 %q must be 64-hex", r.Type, r.SHA256)
		}
	}
	// summary integrity: an independent recompute MUST equal the stored summary.
	want := computeSummary(b.Gates)
	if want.RequiredTotal != b.Summary.RequiredTotal ||
		want.RequiredPassed != b.Summary.RequiredPassed ||
		want.RequiredFailed != b.Summary.RequiredFailed ||
		want.Skipped != b.Summary.Skipped ||
		want.EnterpriseReady != b.Summary.EnterpriseReady {
		return errors.New("summary does not match an independent recompute of the gates")
	}
	return nil
}

// ---- parsing helpers --------------------------------------------------------

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// normalizeStatus maps the pass/fail/skip vocabulary AND GitHub's
// needs.<job>.result vocabulary (success/failure/cancelled/skipped) to the
// canonical status. Unknown/empty -> skip (honest "not confirmed", never a
// silent pass); cancelled/timed_out -> fail (a required gate that was cut is not
// ready).
func normalizeStatus(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pass", "passed", "success", "succeeded":
		return "pass", nil
	case "fail", "failed", "failure", "cancelled", "canceled", "timed_out", "action_required":
		return "fail", nil
	case "skip", "skipped", "neutral", "", "null":
		return "skip", nil
	default:
		return "", fmt.Errorf("unrecognised status %q", s)
	}
}

// parseGateFlag parses `id=status[,evidence=url][,note=text]`. `note` is greedy:
// everything after `,note=` is the note (so it may contain commas). The optional
// `evidence` segment therefore precedes any note.
func parseGateFlag(s string) (gateInput, error) {
	head, rest, _ := strings.Cut(s, ",")
	id, status, ok := strings.Cut(head, "=")
	if !ok || strings.TrimSpace(id) == "" || strings.TrimSpace(status) == "" {
		return gateInput{}, errors.New("want id=status[,evidence=url][,note=text]")
	}
	gi := gateInput{ID: strings.TrimSpace(id), Status: strings.TrimSpace(status)}

	// Peel a greedy note off the end first, so a comma-bearing note survives.
	if i := strings.Index(rest, "note="); i >= 0 {
		gi.Note = strings.TrimSpace(rest[i+len("note="):])
		rest = strings.TrimRight(rest[:i], ", ")
	}
	for _, part := range splitTopComma(rest) {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return gateInput{}, fmt.Errorf("bad key=value segment %q", part)
		}
		switch strings.TrimSpace(k) {
		case "evidence":
			gi.Evidence = strings.TrimSpace(v)
		default:
			return gateInput{}, fmt.Errorf("unknown segment key %q (want evidence= or note=)", k)
		}
	}
	return gi, nil
}

// splitTopComma splits on commas; used for the optional evidence segment(s).
func splitTopComma(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func parseArtifactFlag(s string) (Artifact, error) {
	name, sha, ok := strings.Cut(s, "=")
	name, sha = strings.TrimSpace(name), strings.TrimSpace(sha)
	if !ok || name == "" || !reSHA256.MatchString(sha) {
		return Artifact{}, errors.New("want name=<64-hex sha256>")
	}
	return Artifact{Name: name, Digest: Digest{SHA256: sha}}, nil
}

func parseReferenceFlag(s string) (Reference, error) {
	head, rest, _ := strings.Cut(s, ",")
	ty, uri, ok := strings.Cut(head, "=")
	ty, uri = strings.TrimSpace(ty), strings.TrimSpace(uri)
	if !ok || !validRefTy[ty] || uri == "" {
		return Reference{}, errors.New("want type=uri[,sha256=hex] with a valid reference type")
	}
	ref := Reference{Type: ty, URI: uri}
	for _, part := range splitTopComma(rest) {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(k) != "sha256" {
			return Reference{}, fmt.Errorf("unknown reference segment %q", part)
		}
		ref.SHA256 = strings.TrimSpace(v)
	}
	return ref, nil
}

// parseChecksums parses a `sha256␠␠name` (GNU coreutils) SHA256SUMS file into
// artifact digests.
func parseChecksums(path string) ([]Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Artifact
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed SHA256SUMS line: %q", line)
		}
		sha := strings.ToLower(fields[0])
		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*") // coreutils binary marker
		if !reSHA256.MatchString(sha) {
			return nil, fmt.Errorf("bad sha256 in SHA256SUMS line: %q", line)
		}
		out = append(out, Artifact{Name: name, Digest: Digest{SHA256: sha}})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no checksum lines found")
	}
	return out, nil
}

func loadGatesFile(path string) ([]gateInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []gateInput
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("gates-file %q: expected a JSON array of {id,status,...}: %w", path, err)
	}
	return arr, nil
}

func upsertGate(gs []gateInput, gi gateInput) []gateInput {
	for i := range gs {
		if gs[i].ID == gi.ID {
			gs[i] = gi
			return gs
		}
	}
	return append(gs, gi)
}

// crossCheckSchema loads the shipped JSON-schema and asserts its gate-id enum is
// exactly the registry set, so policy G and the schema cannot drift. A missing
// file is a soft skip (the tool must still run where the schema isn't checked out).
func crossCheckSchema(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "release-evidence: schema %q absent: skipping gate-id cross-check\n", path)
			return nil
		}
		return err
	}
	// Navigate properties.gates.items.properties.id.enum without a schema lib.
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %q: %w", path, err)
	}
	enum, err := digEnum(doc)
	if err != nil {
		return fmt.Errorf("%q: %w", path, err)
	}
	want := map[string]bool{}
	for _, g := range registry {
		want[g.id] = true
	}
	got := map[string]bool{}
	for _, e := range enum {
		got[e] = true
	}
	var missing, extra []string
	for id := range want {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	for id := range got {
		if !want[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("registry vs schema gate-id enum drift (in-registry-not-schema=%v, in-schema-not-registry=%v)", missing, extra)
	}
	return nil
}

func digEnum(doc map[string]any) ([]string, error) {
	step := func(m map[string]any, k string) (map[string]any, error) {
		v, ok := m[k].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("missing object at .%s", k)
		}
		return v, nil
	}
	var err error
	m := doc
	for _, k := range []string{"properties", "gates", "items", "properties", "id"} {
		if m, err = step(m, k); err != nil {
			return nil, err
		}
	}
	raw, ok := m["enum"].([]any)
	if !ok {
		return nil, errors.New("no enum at properties.gates.items.properties.id")
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		s, ok := e.(string)
		if !ok {
			return nil, errors.New("non-string in gate-id enum")
		}
		out = append(out, s)
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
