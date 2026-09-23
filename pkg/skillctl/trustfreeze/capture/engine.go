// Package capture is the Trust Freeze capture engine (SPEC-0467 section
// 5.6): it
// runs the probes of a profile, turns their results into a capture bundle
// and writes it through the core bundle writer. It never approves, signs or
// creates a baseline (SPEC-0470 TF05-R2, TF05-R6).
package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/common"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/linux"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Engine errors.
var (
	ErrInvalidOptions = errors.New("capture: invalid options")
	ErrUnknownProbe   = errors.New("capture: probe is not part of the profile")
)

// Reasons and error classes the engine records.
const (
	ReasonPlatformNotSupported = "platform_not_supported"
	ReasonPrivilegeRequired    = "requires_elevated_privilege"
	ClassInvalidSupport        = "invalid_support_result"
	ClassInvalidStatus         = "invalid_status"
)

// Options configures one capture.
type Options struct {
	Profile  Profile
	Registry *probe.Registry
	// Host is the observed host. Its Runner is wrapped per probe run.
	Host probe.HostContext
	// Redactor for everything persisted; nil means DefaultRedactor(HomeRoot).
	Redactor *redact.Redactor
	// Limits per probe run; zero fields take the defaults.
	Limits probe.Limits
	// Output directory of the bundle; see trustfreeze.NewWriter.
	Output   string
	Force    bool
	HomeRoot string
	// ToolVersion of skillctl, recorded in capture.json.
	ToolVersion string
	// Actor who ran the capture, when known (SPEC-0470 TF05-R7). Empty or an
	// identifier (trustfreeze.ValidateIdentifier).
	Actor string
	// Probes restricts the run to these probe ids of the profile.
	Probes []string
	// ExcludeProbes skips these probe ids of the profile. Every profile probe
	// that is not run (skipped here or left out of Probes) is still recorded,
	// as unsupported with reason excluded_by_operator: a skipped required
	// probe makes the capture incomplete, and compare reports every skipped
	// probe as a collection gap (SPEC-0469 section 4.2).
	ExcludeProbes []string
	// ProbeTimeout overrides the timeout of every probe run.
	ProbeTimeout time.Duration
	// Capabilities resolves the capabilities of the collected artifacts. Nil
	// means DefaultCapabilityResolver(Host.GOOS); a resolver with an empty ID
	// or without a Resolve function resolves nothing and writes no document.
	Capabilities *CapabilityResolver
}

// resolver returns the capability resolver of this run: the configured one,
// else the default of the observed platform, else nil.
func (o Options) resolver() *CapabilityResolver {
	if o.Capabilities != nil {
		return o.Capabilities
	}
	return DefaultCapabilityResolver(o.Host.GOOS)
}

// Result is a written capture bundle.
type Result struct {
	Dir      string
	Manifest trustfreeze.Manifest
	Capture  trustfreeze.CaptureDoc
	Results  []trustfreeze.ProbeResult
	// Capabilities is the written state/capabilities.json; nil when no
	// resolver ran on this platform.
	Capabilities *trustfreeze.CapabilitiesDoc
}

// Complete reports whether the capture is complete.
func (r *Result) Complete() bool {
	return r.Capture.Completeness.Status == trustfreeze.CompletenessComplete
}

// DefaultRegistry returns a registry with every probe of this build. The
// platform probes are registered on every operating system: their descriptors
// name the platforms they are implemented for, so a probe that cannot run
// here is recorded as unsupported with the platform as the reason, instead of
// being left out and read as not implemented at all (SPEC-0467 R3).
func DefaultRegistry() (*probe.Registry, error) {
	reg := probe.NewRegistry()
	if err := common.Register(reg); err != nil {
		return nil, err
	}
	if err := linux.Register(reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// DefaultHostContext returns the production host context with the file
// roots the registered probes read.
func DefaultHostContext() probe.HostContext {
	return probe.NewHostContext(DefaultAllowedRoots(runtime.GOOS))
}

// DefaultAllowedRoots returns the file roots of every registered probe on
// goos, sorted and without duplicates. A path outside them is refused by the
// restricted file reader, so a probe whose roots are missing here reports
// not_applicable instead of the real state.
func DefaultAllowedRoots(goos string) []string {
	roots := append(common.AllowedRoots(goos), linux.AllowedRoots(goos)...)
	sort.Strings(roots)
	return slices.Compact(roots)
}

// LinuxCapabilityResolverID names the capability resolver of the linux
// platform package in state/capabilities.json. The version is part of the id
// because the rules decide what the document says.
const LinuxCapabilityResolverID = "linux.privilege/v1"

// CapabilityResolver derives capabilities from the artifacts of one capture
// (SPEC-0466 section 4.6). Resolve is pure: artifacts in, capabilities and
// diagnostics out, no file system, no command, no clock. An error aborts the
// capture, so a resolver that cannot decide reports a diagnostic instead.
type CapabilityResolver struct {
	// ID names the resolver in state/capabilities.json.
	ID string
	// Resolve turns the sorted artifacts of the capture into capabilities.
	Resolve func(context.Context, []trustfreeze.Artifact) ([]trustfreeze.Capability, []trustfreeze.Diagnostic, error)
}

// DefaultCapabilityResolver returns the capability resolver of goos, or nil
// where this build has none. A capture without a resolver writes no
// state/capabilities.json at all, so the absence of the file says "nobody
// looked", never "this host grants nothing" (SPEC-0466 section 5.7).
func DefaultCapabilityResolver(goos string) *CapabilityResolver {
	if goos != string(probe.PlatformLinux) {
		return nil
	}
	r := linux.CapabilityResolver{}
	return &CapabilityResolver{ID: LinuxCapabilityResolverID, Resolve: r.Resolve}
}

// DefaultRedactor returns the redactor of RedactionPolicyDefault: the default
// patterns plus the home root, so user-specific paths never reach a bundle.
// The home root is replaced as a literal and in every spelling a tool may
// print (see homePathPattern). A home root too short to replace safely is
// skipped.
func DefaultRedactor(homeRoot string) (*redact.Redactor, error) {
	if len(strings.Trim(homeRoot, `/\`)) < 3 {
		return redact.New()
	}
	opts := []redact.Option{redact.WithLiteral(homeRoot, "home_path")}
	if p := homePathPattern(homeRoot); p != "" {
		opts = append(opts, redact.WithPattern("home_path", p, 0))
	}
	return redact.New(opts...)
}

// homePathPattern matches homeRoot without regard to letter case, with
// either separator or a JSON-escaped backslash between its segments, and,
// for a drive path, also in its WSL form /mnt/<drive>/... So C:\Users\alice
// is found as c:\users\alice, C:/Users/alice, C:\\Users\\alice and
// /mnt/c/Users/alice. Not covered: a home share or drive that differs from
// the profile directory, and the 8.3 short form.
func homePathPattern(homeRoot string) string {
	segs := strings.FieldsFunc(homeRoot, func(r rune) bool { return r == '/' || r == '\\' })
	if len(segs) == 0 {
		return ""
	}
	const sep = `(?:\\\\|\\|/)`
	drive := ""
	if s := segs[0]; len(s) == 2 && s[1] == ':' && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		drive, segs = s[:1], segs[1:]
	}
	if len(segs) == 0 {
		return ""
	}
	quoted := make([]string, len(segs))
	for i, seg := range segs {
		quoted[i] = regexp.QuoteMeta(seg)
	}
	body := strings.Join(quoted, sep)
	if drive == "" {
		return `(?i)` + sep + body
	}
	return `(?i)(?:` + drive + `:` + sep + `|/mnt/` + drive + `/)` + body
}

func (o Options) validate() error {
	switch {
	case o.Registry == nil:
		return fmt.Errorf("%w: no registry", ErrInvalidOptions)
	case strings.TrimSpace(o.ToolVersion) == "":
		return fmt.Errorf("%w: empty tool version", ErrInvalidOptions)
	case strings.TrimSpace(o.Output) == "":
		return fmt.Errorf("%w: empty output", ErrInvalidOptions)
	case o.Profile.Digest() == "":
		return fmt.Errorf("%w: profile was not loaded with ParseProfile or BuiltinProfile", ErrInvalidOptions)
	case o.ProbeTimeout < 0:
		return fmt.Errorf("%w: negative probe timeout", ErrInvalidOptions)
	case o.Actor != "" && trustfreeze.ValidateIdentifier(o.Actor) != nil:
		// The actor reaches the signed approval (identities.capture_actor),
		// which accepts only this charset (SPEC-0470 section 4.2).
		return fmt.Errorf("%w: actor must be 1 to %d characters from %s", ErrInvalidOptions, trustfreeze.MaxIdentifierLen, trustfreeze.IdentifierCharset)
	}
	if err := o.Profile.validate(); err != nil {
		return err
	}
	if err := o.Limits.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	return o.Host.Validate()
}

// selectProbes applies Probes and ExcludeProbes to the profile. It returns
// every probe id of the profile in order and the set of those not to run.
func selectProbes(p Profile, include, exclude []string) ([]string, map[string]bool, error) {
	for _, id := range append(append([]string{}, include...), exclude...) {
		if !p.Has(id) {
			return nil, nil, fmt.Errorf("%w: %q (profile %s)", ErrUnknownProbe, id, p.ID)
		}
	}
	in := map[string]bool{}
	for _, id := range include {
		in[id] = true
	}
	out := map[string]bool{}
	for _, id := range exclude {
		out[id] = true
	}
	ids := p.ProbeIDs()
	skip := map[string]bool{}
	for _, id := range ids {
		if (len(include) > 0 && !in[id]) || out[id] {
			skip[id] = true
		}
	}
	return ids, skip, nil
}

// Run captures the host into a new capture bundle at opts.Output. The
// bundle is written to a staging directory next to the target and renamed
// into place only after it verified. A probe failure never aborts the
// capture; it is recorded (SPEC-0467 R3, R10). Run aborts only on invalid
// options, an unusable target, a canceled context or a write failure.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	ids, skip, err := selectProbes(opts.Profile, opts.Probes, opts.ExcludeProbes)
	if err != nil {
		return nil, err
	}
	subject, _, err := opts.Host.Subject()
	if err != nil {
		return nil, err
	}
	red := opts.Redactor
	if red == nil {
		if red, err = DefaultRedactor(opts.HomeRoot); err != nil {
			return nil, err
		}
	}
	clock := opts.Host.Clock
	started := clock.Now()

	w, err := trustfreeze.NewWriter(opts.Output, trustfreeze.WriterOptions{Kind: trustfreeze.KindCapture, Force: opts.Force, HomeRoot: opts.HomeRoot})
	if err != nil {
		return nil, err
	}
	res, err := run(ctx, opts, ids, skip, subject, red, started, w)
	if err != nil {
		return nil, errors.Join(err, w.Abort())
	}
	return res, nil
}

type probeRun struct {
	result   trustfreeze.ProbeResult
	evidence []probe.EvidenceItem
}

func run(ctx context.Context, opts Options, ids []string, skip map[string]bool, subject trustfreeze.Subject, red *redact.Redactor, started time.Time, w *trustfreeze.Writer) (*Result, error) {
	runs := make([]probeRun, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("capture canceled before %s: %w", id, err)
		}
		if skip[id] {
			runs = append(runs, excludedProbe(opts, id))
			continue
		}
		pr := runProbe(ctx, opts, id, red)
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("capture canceled during %s: %w", id, err)
		}
		runs = append(runs, pr)
	}
	dedupeArtifacts(runs)

	var results []trustfreeze.ProbeResult
	var artifacts []trustfreeze.Artifact
	for i := range runs {
		r := &runs[i].result
		if len(runs[i].evidence) != len(r.RawEvidence) {
			return nil, fmt.Errorf("%s: %d evidence files but %d references", r.ProbeID, len(runs[i].evidence), len(r.RawEvidence))
		}
		for j, item := range runs[i].evidence {
			ref, err := w.WriteEvidence(item.Ref.Path, item.Data)
			if err != nil {
				return nil, fmt.Errorf("%s: evidence %s: %w", r.ProbeID, item.Name, err)
			}
			want := r.RawEvidence[j]
			if ref.Path != want.Path || ref.Size != want.Size || ref.SHA256 != want.SHA256 {
				return nil, fmt.Errorf("%s: evidence %s does not match its reference", r.ProbeID, item.Name)
			}
		}
		p, err := trustfreeze.ProbeResultPath(r.ProbeID)
		if err != nil {
			return nil, err
		}
		if err := w.WriteJSON(p, *r); err != nil {
			return nil, fmt.Errorf("%s: %w", r.ProbeID, err)
		}
		results = append(results, *r)
		artifacts = append(artifacts, r.NormalizedState...)
	}
	trustfreeze.SortArtifacts(artifacts)
	if artifacts == nil {
		artifacts = []trustfreeze.Artifact{}
	}
	if err := w.WriteJSON(trustfreeze.StateDeviceFile, trustfreeze.StateDoc{Artifacts: artifacts}); err != nil {
		return nil, err
	}
	caps, err := resolveCapabilities(ctx, opts, artifacts)
	if err != nil {
		return nil, err
	}
	if caps != nil {
		if err := w.WriteJSON(trustfreeze.StateCapabilitiesFile, *caps); err != nil {
			return nil, err
		}
	}
	finished := opts.Host.Clock.Now()
	doc := trustfreeze.CaptureDoc{
		SchemaVersion: trustfreeze.SchemaCapture,
		Kind:          trustfreeze.KindCapture,
		Capture: trustfreeze.CaptureMeta{
			StartedAt:   trustfreeze.FormatTime(started),
			FinishedAt:  trustfreeze.FormatTime(finished),
			Tool:        trustfreeze.CaptureTool,
			ToolVersion: opts.ToolVersion,
			Profile:     opts.Profile.Ref(),
			Actor:       opts.Actor,
		},
		Subject:      subject,
		Completeness: trustfreeze.ComputeCompleteness(opts.Profile.Required, results),
		Probes:       trustfreeze.Summarize(results),
	}
	if err := w.WriteJSON(trustfreeze.CaptureFile, doc); err != nil {
		return nil, err
	}
	m, err := w.Finalize(trustfreeze.ManifestHeader{
		Kind:      trustfreeze.KindCapture,
		BundleID:  trustfreeze.BundleID(trustfreeze.KindCapture, finished, subject.ID),
		CreatedAt: finished,
		Subject:   subject,
	})
	if err != nil {
		return nil, err
	}
	return &Result{Dir: w.Target(), Manifest: m, Capture: doc, Results: results, Capabilities: caps}, nil
}

// resolveCapabilities runs the capability resolver of this capture over the
// artifacts every probe produced (SPEC-0466 section 4.6). It returns nil when
// no resolver is configured for the platform: the bundle then has no
// state/capabilities.json, which says that nobody resolved capabilities here,
// not that the host grants none.
//
// The resolver sees only what the probes recorded, so its statements are
// exactly as complete as the capture: a probe that was permission_denied
// leaves its privileges unresolved, and the collection gap in capture.json is
// what says so.
func resolveCapabilities(ctx context.Context, opts Options, artifacts []trustfreeze.Artifact) (*trustfreeze.CapabilitiesDoc, error) {
	r := opts.resolver()
	if r == nil || r.Resolve == nil || strings.TrimSpace(r.ID) == "" {
		return nil, nil
	}
	caps, diags, err := r.Resolve(ctx, artifacts)
	if err != nil {
		return nil, fmt.Errorf("capability resolver %s: %w", r.ID, err)
	}
	doc := trustfreeze.CapabilitiesDoc{Resolver: r.ID, Capabilities: []trustfreeze.Capability{}, Diagnostics: diags}
	seen := map[string]bool{}
	for _, c := range caps {
		switch {
		case strings.TrimSpace(c.ID) == "":
			doc.Diagnostics = append(doc.Diagnostics, trustfreeze.Diagnostic{
				Code: DiagCapabilityDropped, Message: "a capability without an id was dropped",
			})
		case seen[c.ID]:
			doc.Diagnostics = append(doc.Diagnostics, trustfreeze.Diagnostic{
				Code: DiagCapabilityDropped, Field: c.ID, Message: "a second capability with this id was dropped",
			})
		default:
			seen[c.ID] = true
			doc.Capabilities = append(doc.Capabilities, c)
		}
	}
	trustfreeze.SortCapabilities(doc.Capabilities)
	return &doc, nil
}

// DiagCapabilityDropped: the engine dropped a capability the resolver
// returned, because its id was empty or already used.
const DiagCapabilityDropped = "capability_dropped"

// excludedProbe records a profile probe the operator chose not to run, so
// the bundle still names every probe of its profile.
func excludedProbe(opts Options, id string) probeRun {
	r := trustfreeze.ProbeResult{
		ProbeID:   id,
		Status:    trustfreeze.StatusUnsupported,
		Reason:    trustfreeze.ReasonExcludedByOperator,
		Support:   trustfreeze.SupportRecord{Available: false, Reason: trustfreeze.ReasonExcludedByOperator},
		StartedAt: trustfreeze.FormatTime(opts.Host.Clock.Now()),
		Privilege: opts.Host.Privilege,
	}
	if p, ok := opts.Registry.Get(id); ok {
		r.ProbeVersion = p.Descriptor().Version
	}
	return probeRun{result: r}
}

// probeTimeout picks the timeout of one run: the override, else the probe
// default, else the limit.
func probeTimeout(opts Options, d probe.ProbeDescriptor) time.Duration {
	switch {
	case opts.ProbeTimeout > 0:
		return opts.ProbeTimeout
	case d.DefaultTimeout > 0:
		return d.DefaultTimeout
	}
	return opts.Limits.WithDefaults().Timeout
}

type outcome struct {
	support   probe.SupportResult
	result    trustfreeze.ProbeResult
	collected bool
	panicked  bool
	panicMsg  string
}

// runProbe runs Support then Collect of one probe under its timeout, with panics
// recovered as failed (SPEC-0467 section 5.6). The probe runs in its own
// goroutine, so a probe that ignores its context cannot stall the capture; when
// abandoned, its runner and evidence sink refuse further use.
func runProbe(ctx context.Context, opts Options, id string, red *redact.Redactor) probeRun {
	host := opts.Host
	start := host.Clock.Now()
	base := trustfreeze.ProbeResult{
		ProbeID:   id,
		StartedAt: trustfreeze.FormatTime(start),
		Privilege: host.Privilege,
	}
	p, ok := opts.Registry.Get(id)
	if !ok {
		base.Status = trustfreeze.StatusUnsupported
		base.Reason = trustfreeze.ReasonNotImplemented
		base.Support = trustfreeze.SupportRecord{Available: false, Reason: trustfreeze.ReasonNotImplemented}
		return probeRun{result: base}
	}
	d := p.Descriptor()
	base.ProbeVersion = d.Version
	if !d.SupportsPlatform(host.GOOS) {
		base.Status = trustfreeze.StatusUnsupported
		base.Reason = ReasonPlatformNotSupported + ": " + host.GOOS
		base.Support = trustfreeze.SupportRecord{Available: false, Reason: base.Reason}
		return probeRun{result: base}
	}
	if d.RequiredPrivilege == probe.PrivilegeElevated && host.Privilege != probe.PrivilegeElevated {
		// Trust Freeze never elevates (SPEC-0467 R6): record, do not ask.
		base.Status = trustfreeze.StatusPermissionDenied
		base.Reason = ReasonPrivilegeRequired
		base.Support = trustfreeze.SupportRecord{Available: false, Reason: base.Reason}
		return probeRun{result: base}
	}

	timeout := probeTimeout(opts, d)
	limits := opts.Limits.WithDefaults()
	limits.Timeout = timeout
	rec := probe.NewRecordingRunner(host.Runner, limits, red)
	ev := probe.NewEvidenceBuffer(id, limits)
	hc := host
	hc.Runner = rec

	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if r := recover(); r != nil {
				o.panicked, o.panicMsg = true, fmt.Sprint(r)
			}
			ch <- o
		}()
		o.support = p.Support(pctx, hc)
		if o.support.Validate() != nil || !o.support.Available {
			return
		}
		o.result = p.Collect(pctx, probe.CollectContext{
			HostContext: hc, ProbeID: id, Redactor: red, Limits: limits, Evidence: ev, Support: o.support,
		})
		o.collected = true
	}()

	var o outcome
	timedOut := false
	select {
	case o = <-ch:
	case <-pctx.Done():
		select {
		case o = <-ch:
		default:
			timedOut = true
		}
	}
	tools, redactionFailed, truncated := rec.Close()
	items := ev.Close()
	refused := ev.Refused()
	duration := host.Clock.Now().Sub(start).Milliseconds()

	r := base
	switch {
	case timedOut:
		r.Status = trustfreeze.StatusTimeout
		r.Reason = fmt.Sprintf("probe did not finish within %s", timeout)
		r.Error = &trustfreeze.ProbeError{Class: probe.ClassTimeout, Message: r.Reason}
	case o.panicked:
		r.Status = trustfreeze.StatusFailed
		r.Reason = "probe panicked"
		r.Error = &trustfreeze.ProbeError{Class: probe.ClassPanic, Message: o.panicMsg}
		r.Support = o.support.Record()
	case o.support.Validate() != nil:
		r.Status = trustfreeze.StatusFailed
		r.Reason = "probe returned an invalid support result"
		r.Error = &trustfreeze.ProbeError{Class: ClassInvalidSupport, Message: o.support.Validate().Error()}
	case !o.support.Available:
		r.Status = o.support.Status
		r.Reason = o.support.Reason
		r.Support = o.support.Record()
	default:
		r = o.result
		if !r.Status.Valid() {
			r = base
			r.Status = trustfreeze.StatusFailed
			r.Reason = "probe returned an invalid status"
			r.Error = &trustfreeze.ProbeError{Class: ClassInvalidStatus}
		}
		r.Support = o.support.Record()
	}
	// The engine, not the probe, is the authority for these fields.
	r.ProbeID, r.ProbeVersion = id, d.Version
	r.StartedAt, r.DurationMS = base.StartedAt, duration
	r.Privilege = host.Privilege
	r.Tools = nil
	if len(tools) > 0 {
		r.Tools = tools
	}
	for _, s := range truncated {
		r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: trustfreeze.DiagOutputTruncated, Message: s + " exceeded its output limit"})
		lowerToPartial(&r, "output truncated")
	}
	if redactionFailed && !hasWarning(r, trustfreeze.DiagRedactionFailed) {
		r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: trustfreeze.DiagRedactionFailed, Message: "command output dropped (fail-closed)"})
	}
	if redactionFailed || hasWarning(r, trustfreeze.DiagRedactionFailed) {
		lowerToPartial(&r, "redaction failed")
	}
	// Evidence the sink refused (name, duplicate, file size or count limit)
	// caps the probe at partial, whatever the probe did with the error
	// (SPEC-0467 section 5.3).
	if refused > 0 {
		if !hasWarning(r, probe.DiagEvidenceDropped) {
			r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: probe.DiagEvidenceDropped, Message: fmt.Sprintf("%d evidence file(s) refused by the evidence sink", refused)})
		}
		lowerToPartial(&r, "evidence dropped")
	}
	validateArtifacts(&r)

	// Evidence references become part of the result before the final
	// redaction pass, so their probe-provided fields are redacted too. An
	// evidence name that redaction would change carries a secret in the
	// file name itself: that file is dropped. The evidence bytes pass the
	// final redactor as well (reRedactEvidence).
	finalRed := red.WithSecrets(rec.ArgSecrets())
	items = keepCleanEvidence(ctx, finalRed, items, &r)
	items = reRedactEvidence(ctx, finalRed, items, limits.MaxFileBytes, &r)
	r.RawEvidence = nil
	for _, it := range items {
		r.RawEvidence = append(r.RawEvidence, it.Ref)
	}

	final, log, err := redactResult(ctx, finalRed, r)
	if err != nil {
		// Fail-closed: nothing the probe produced is persisted.
		f := base
		f.ProbeVersion, f.DurationMS = d.Version, duration
		f.Support = r.Support
		f.Status = trustfreeze.StatusFailed
		f.Reason = "the probe result could not be redacted and was dropped"
		f.Error = &trustfreeze.ProbeError{Class: probe.ClassRedactionFailed}
		f.Warnings = []trustfreeze.Diagnostic{{Code: trustfreeze.DiagRedactionFailed, Message: "probe result and evidence dropped (fail-closed)"}}
		return probeRun{result: f}
	}
	if n := log.Total(); n > 0 {
		final.Warnings = append(final.Warnings, trustfreeze.Diagnostic{
			Code:    probe.DiagValueRedacted,
			Message: fmt.Sprintf("%d value(s) redacted in the probe result (%s)", n, strings.Join(log.Classes(), ", ")),
		})
	}
	finalizeArtifacts(&final)
	sortWarnings(final.Warnings)
	return probeRun{result: final, evidence: items}
}

// keepCleanEvidence drops evidence whose name the redactor would change.
func keepCleanEvidence(ctx context.Context, red *redact.Redactor, items []probe.EvidenceItem, r *trustfreeze.ProbeResult) []probe.EvidenceItem {
	var kept []probe.EvidenceItem
	for _, it := range items {
		name, _, err := red.RedactString(context.WithoutCancel(ctx), it.Name)
		if err != nil || name != it.Name {
			r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: probe.DiagEvidenceDropped, Message: "an evidence file name contained a redactable value"})
			lowerToPartial(r, "evidence dropped")
			continue
		}
		kept = append(kept, it)
	}
	return kept
}

// reRedactEvidence passes every evidence file through the capture's final
// redactor (the capture redactor plus every argument secret of this probe
// run) before anything is written (TF02-AC3, SPEC-0467 sections 2.3 and
// 5.2). redact.Redacted proves that some redactor ran, not this one: a probe
// may have used another redactor, and one command may print a secret that
// only another command's arguments reveal. Changed bytes replace the item and
// its size and digest; a file that cannot be redacted, or that the markers
// push over the file size limit, is dropped and the probe is at most partial.
func reRedactEvidence(ctx context.Context, red *redact.Redactor, items []probe.EvidenceItem, maxBytes int64, r *trustfreeze.ProbeResult) []probe.EvidenceItem {
	var kept []probe.EvidenceItem
	var log redact.RedactionLog
	for _, it := range items {
		rr, err := red.RedactBytes(context.WithoutCancel(ctx), redact.EvidenceDescriptor{ProbeID: r.ProbeID, Name: it.Name}, it.Data.Bytes())
		if err != nil {
			r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: trustfreeze.DiagRedactionFailed, Message: "an evidence file could not be redacted by the capture redactor and was dropped (fail-closed)"})
			lowerToPartial(r, "redaction failed")
			continue
		}
		if rr.Log.Total() > 0 {
			b := rr.Data.Bytes()
			if int64(len(b)) > maxBytes {
				r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: probe.DiagEvidenceDropped, Message: "an evidence file exceeded the file size limit after redaction and was dropped"})
				lowerToPartial(r, "evidence dropped")
				continue
			}
			log = log.Merge(rr.Log)
			it.Data = rr.Data
			it.Ref.Size, it.Ref.SHA256 = int64(len(b)), trustfreeze.SHA256Hex(b)
		}
		kept = append(kept, it)
	}
	if n := log.Total(); n > 0 {
		r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{
			Code:    probe.DiagValueRedacted,
			Message: fmt.Sprintf("%d value(s) redacted in the evidence files (%s)", n, strings.Join(log.Classes(), ", ")),
		})
	}
	return kept
}

// lowerToPartial turns captured into partial; worse statuses stay.
func lowerToPartial(r *trustfreeze.ProbeResult, reason string) {
	if r.Status == trustfreeze.StatusCaptured {
		r.Status = trustfreeze.StatusPartial
		r.Reason = reason
	}
}

func hasWarning(r trustfreeze.ProbeResult, code string) bool {
	for _, w := range r.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// validateArtifacts drops artifacts that cannot be persisted honestly: bad
// id (absolute or user-specific path), unknown state, confidence or
// sensitivity. A drop lowers captured to partial.
func validateArtifacts(r *trustfreeze.ProbeResult) {
	kept := r.NormalizedState[:0:0]
	for _, a := range r.NormalizedState {
		var problem string
		switch {
		case trustfreeze.ValidateArtifactID(a.ID) != nil:
			problem = "invalid artifact id"
		case !a.State.Valid():
			problem = "invalid evidence state"
		case !a.Provenance.Confidence.Valid():
			problem = "invalid confidence"
		case !a.Sensitivity.Valid():
			problem = "invalid sensitivity"
		case a.ValidateAttributeClasses() != nil:
			problem = "invalid attribute class: " + a.ValidateAttributeClasses().Error()
		}
		if problem != "" {
			r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: probe.DiagArtifactDropped, Message: problem})
			lowerToPartial(r, "artifact dropped")
			continue
		}
		kept = append(kept, a)
	}
	r.NormalizedState = nil
	if len(kept) > 0 {
		r.NormalizedState = kept
	}
}

// finalizeArtifacts recomputes every artifact digest after redaction and
// sorts the artifacts by id.
func finalizeArtifacts(r *trustfreeze.ProbeResult) {
	for i := range r.NormalizedState {
		if d, err := trustfreeze.ComputeArtifactDigest(r.NormalizedState[i]); err == nil {
			r.NormalizedState[i].Digest = d
		}
	}
	trustfreeze.SortArtifacts(r.NormalizedState)
}

// dedupeArtifacts keeps the first artifact per id (probes run in id order)
// and drops later duplicates with a diagnostic.
func dedupeArtifacts(runs []probeRun) {
	owner := map[string]string{}
	for i := range runs {
		r := &runs[i].result
		kept := r.NormalizedState[:0:0]
		for _, a := range r.NormalizedState {
			if prev, dup := owner[a.ID]; dup {
				r.Warnings = append(r.Warnings, trustfreeze.Diagnostic{Code: probe.DiagArtifactDropped, Message: a.ID + " is already reported by " + prev})
				lowerToPartial(r, "artifact dropped")
				continue
			}
			owner[a.ID] = r.ProbeID
			kept = append(kept, a)
		}
		r.NormalizedState = nil
		if len(kept) > 0 {
			r.NormalizedState = kept
		}
		sortWarnings(r.Warnings)
	}
}

func sortWarnings(ws []trustfreeze.Diagnostic) {
	sort.SliceStable(ws, func(i, j int) bool {
		a, b := ws[i], ws[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Message < b.Message
	})
}

// redactResult is the last redaction pass over everything a probe result
// carries as text (SPEC-0467 R5, TF02-AC3): the result is decoded into a
// generic JSON value, every string is redacted, every value under a
// sensitive key is replaced, and the value is decoded back strictly. A probe
// that put a secret into an attribute, a message or an error therefore
// cannot persist it. Any failure is returned; the caller drops the result.
func redactResult(ctx context.Context, red *redact.Redactor, r trustfreeze.ProbeResult) (trustfreeze.ProbeResult, redact.RedactionLog, error) {
	// The attribute classes are the probe's statement about its fields, not
	// data the probe collected, and they are a map KEYED by attribute names.
	// They are taken out of the document before the pass and put back after
	// it: a declaration must not be redacted because of the name it carries.
	// validateArtifacts has already checked every class.
	policy, sensitive := declaredAttributeKeys(r)
	classes := make([]map[string]trustfreeze.AttributeClass, len(r.NormalizedState))
	stripped := r
	stripped.NormalizedState = make([]trustfreeze.Artifact, len(r.NormalizedState))
	copy(stripped.NormalizedState, r.NormalizedState)
	for i := range stripped.NormalizedState {
		classes[i] = stripped.NormalizedState[i].AttributeClasses
		stripped.NormalizedState[i].AttributeClasses = nil
	}
	r = stripped
	b, err := json.Marshal(r)
	if err != nil {
		return trustfreeze.ProbeResult{}, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return trustfreeze.ProbeResult{}, nil, err
	}
	clean, log, err := red.RedactValue(context.WithoutCancel(ctx), redact.ValueContext{
		ProbeID:       r.ProbeID,
		Path:          "$",
		PolicyKeys:    policy,
		SensitiveKeys: sensitive,
	}, generic)
	if err != nil {
		return trustfreeze.ProbeResult{}, nil, err
	}
	b, err = json.Marshal(clean)
	if err != nil {
		return trustfreeze.ProbeResult{}, nil, err
	}
	var out trustfreeze.ProbeResult
	if err := trustfreeze.UnmarshalStrict(b, &out); err != nil {
		return trustfreeze.ProbeResult{}, nil, err
	}
	if len(out.NormalizedState) != len(classes) {
		return trustfreeze.ProbeResult{}, nil, fmt.Errorf("%s: %d artifacts before redaction, %d after", r.ProbeID, len(classes), len(out.NormalizedState))
	}
	for i := range out.NormalizedState {
		out.NormalizedState[i].AttributeClasses = classes[i]
	}
	return out, log, nil
}

// declaredAttributeKeys collects what the probes of this result said about
// their own attributes (trustfreeze.AttributeClass) and returns the two key
// lists the redactor takes. A declaration holds for the whole probe result,
// not for the artifact it stands on: the redaction pass walks a decoded JSON
// document, and every map in it was built by the same probe, so a name it
// calls configuration is configuration wherever that probe wrote it. A name
// declared sensitive by one artifact and policy by another is sensitive,
// which is the fail-closed answer.
func declaredAttributeKeys(r trustfreeze.ProbeResult) (policy, sensitive []string) {
	seenPolicy, seenSensitive := map[string]bool{}, map[string]bool{}
	for _, a := range r.NormalizedState {
		for _, k := range a.AttributeKeysByClass(trustfreeze.AttributeClassPolicy) {
			seenPolicy[k] = true
		}
		for _, k := range a.AttributeKeysByClass(trustfreeze.AttributeClassSensitive) {
			seenSensitive[k] = true
		}
	}
	for k := range seenPolicy {
		if !seenSensitive[k] {
			policy = append(policy, k)
		}
	}
	for k := range seenSensitive {
		sensitive = append(sensitive, k)
	}
	sort.Strings(policy)
	sort.Strings(sensitive)
	return policy, sensitive
}

// ToolUser is the optional interface a probe implements to name the
// executables it runs on the host. `trust-freeze doctor` resolves them
// through the runner's LookPath and never runs one, so an operator learns
// before a capture which tool is missing on this host (SPEC-0471 section
// 11.2). The interface is structural: a probe implements it by declaring the
// method and imports nothing for it.
//
//	func (p myProbe) RequiredTools() []string { return []string{"ss"} }
//
// A probe that does not implement it is not a probe without tools: Plan then
// reports ToolsDeclared false and doctor keeps that probe's tool check
// honest instead of claiming an empty list.
type ToolUser interface {
	RequiredTools() []string
}

// ToolCheck is one executable of a probe, resolved but never run.
type ToolCheck struct {
	// Name is the executable as the probe names it.
	Name string
	// Path is the resolved absolute path; empty when it did not resolve.
	Path string
	// Class is empty when the tool resolved, else the runner's error class
	// (probe.ClassToolMissing, probe.ClassPermissionDenied, ...).
	Class string
	// Detail is the runner's message for a tool that did not resolve.
	Detail string
}

// OK reports a tool that resolved to a path.
func (t ToolCheck) OK() bool { return t.Class == "" }

// PlannedProbe is one row of Plan.
type PlannedProbe struct {
	ProbeID    string
	Required   bool
	Registered bool
	Support    probe.SupportResult
	// ToolsDeclared reports whether the probe names its executables
	// (ToolUser) and this host could resolve them at all: false for an
	// unregistered probe, for one this build does not implement for the
	// platform, and for one that declares no tools.
	ToolsDeclared bool
	// Tools is one entry per declared executable, sorted by name and
	// deduplicated. Empty unless ToolsDeclared.
	Tools []ToolCheck
}

// Plan runs only the Support check of every probe of the profile, and
// resolves the executables a probe declares (ToolUser), for doctor (no
// capture, nothing written, no command run). Unregistered probes are reported
// unsupported with reason not_implemented.
func Plan(ctx context.Context, p Profile, reg *probe.Registry, host probe.HostContext) []PlannedProbe {
	var out []PlannedProbe
	for _, id := range p.ProbeIDs() {
		pp := PlannedProbe{ProbeID: id, Required: p.IsRequired(id)}
		pr, ok := reg.Get(id)
		switch {
		case !ok:
			pp.Support = probe.Unsupported(trustfreeze.ReasonNotImplemented)
		case !pr.Descriptor().SupportsPlatform(host.GOOS):
			pp.Registered = true
			pp.Support = probe.Unsupported(ReasonPlatformNotSupported + ": " + host.GOOS)
		default:
			pp.Registered = true
			pp.Support = safeSupport(ctx, pr, host)
			pp.ToolsDeclared, pp.Tools = resolveTools(pr, host.Runner)
		}
		out = append(out, pp)
	}
	return out
}

// resolveTools asks the probe for the executables it uses and resolves each
// one with the runner's LookPath. LookPath only searches the runner's fixed
// directories; it starts no process, so doctor learns what is installed
// without running anything (SPEC-0467 R6, SPEC-0471 section 11.2). A probe
// that declares no tool, or none the host could be asked about, reports
// declared false.
func resolveTools(p probe.Probe, runner probe.CommandRunner) (bool, []ToolCheck) {
	u, ok := p.(ToolUser)
	if !ok || runner == nil {
		return false, nil
	}
	names := append([]string(nil), u.RequiredTools()...)
	sort.Strings(names)
	var out []ToolCheck
	var last string
	for i, name := range names {
		if strings.TrimSpace(name) == "" || (i > 0 && name == last) {
			continue
		}
		last = name
		c := ToolCheck{Name: name}
		path, err := runner.LookPath(name)
		if err != nil {
			c.Class, c.Detail = probe.ErrorClass(err), err.Error()
		} else {
			c.Path = path
		}
		out = append(out, c)
	}
	return len(out) > 0, out
}

func safeSupport(ctx context.Context, p probe.Probe, host probe.HostContext) (s probe.SupportResult) {
	d := p.Descriptor()
	timeout := d.DefaultTimeout
	if timeout <= 0 {
		timeout = probe.DefaultTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan probe.SupportResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- probe.SupportResult{Status: trustfreeze.StatusFailed, Reason: "support check panicked"}
			}
		}()
		ch <- p.Support(sctx, host)
	}()
	select {
	case s = <-ch:
	case <-sctx.Done():
		s = probe.SupportResult{Status: trustfreeze.StatusTimeout, Reason: "support check timed out"}
	}
	return s
}
