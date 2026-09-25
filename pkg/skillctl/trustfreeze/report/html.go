package report

// The report as one self-contained page (FR-0472). The page is built from the
// same projection as the JSON and the YAML: it shows what the bundle says,
// evaluates nothing and decides nothing. It carries no script, no stylesheet,
// no font, no image and no data URI, because a freeze is read on hosts that
// may have no network. Every value of the report goes into a text node or a
// table cell, never into an attribute and never into the style block, so the
// escaping of html/template is correct whatever a host wrote into its own
// configuration.

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/policy"
)

//go:embed report.html.tmpl
var htmlTemplateSource string

// htmlTemplate is parsed once and only executed afterwards, which is safe for
// concurrent use. The template text is normalized to LF first: go:embed takes
// the file as it lies on disk, so a CRLF checkout (core.autocrlf=true on
// Windows) would otherwise put carriage returns into every page and give the
// same bundle two different report_sha256 values depending on how the
// repository was checked out. A carriage return inside a VALUE is left alone:
// that is what the host wrote, and the page shows what the bundle says.
var htmlTemplate = template.Must(template.New("report").Parse(
	strings.ReplaceAll(htmlTemplateSource, "\r\n", "\n")))

// notRecorded is what a field says that the projection does not carry. A page
// never invents a value and never leaves a row out silently.
const notRecorded = "n/a"

// HTMLOptions carries what the page may say about its own origin.
type HTMLOptions struct {
	// Generator is the skillctl version that renders the page. The report
	// projection does not carry it (it carries the version that made the
	// capture, which is another thing), so the caller hands it in; empty
	// renders "n/a" instead of a guess.
	Generator string
}

// MarshalHTML renders the report as one HTML page with a trailing newline.
// Identical reports give identical bytes.
func MarshalHTML(r Report, opts HTMLOptions) ([]byte, error) {
	page, err := htmlPageOf(r, opts)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, page); err != nil {
		return nil, fmt.Errorf("report: html: %w", err)
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}

// --- the page ----------------------------------------------------------------

type htmlPage struct {
	Kind      string
	Title     string
	Lead      string
	Header    []htmlField
	Digests   []htmlDigest
	Guidance  htmlGuidance
	Capture   *htmlCapture
	Approval  *htmlApproval
	Diff      *htmlDiff
	NotShown  []htmlOmission
	Generator string
	Schema    string
}

// htmlField is one labelled value.
type htmlField struct {
	Name  string
	Value string
}

// htmlDigest is one row of the identity block: the value in full, where it
// comes from, and the command that checks it.
type htmlDigest struct {
	Name    string
	Value   string
	Origin  string
	Command string
}

// htmlGuidance is the guidance for the reader, constant per bundle kind.
type htmlGuidance struct {
	What          string
	Answers       string
	DoesNotAnswer string
	Next          string
	NextCommand   string
	CheckLabel    string
	CheckCommand  string
	Note          string
}

type htmlCapture struct {
	Meta          []htmlField
	Completeness  string
	Required      []string
	Gaps          []htmlGap
	Probes        []htmlProbe
	Capabilities  *htmlCapabilities
	ArtifactCount int
}

type htmlGap struct {
	ProbeID string
	Status  string
	Reason  string
}

type htmlProbe struct {
	ProbeID string
	Status  string
	Reason  string
}

type htmlCapabilities struct {
	Resolver    string
	OrderNote   string
	Lines       []htmlCapability
	Diagnostics []htmlField
}

type htmlCapability struct {
	ID         string
	SubjectID  string
	Action     string
	Resource   string
	Effect     string
	Privilege  string
	Exposure   string
	Scope      string
	State      string
	Confidence string
	Sources    string
	Attributes string
}

type htmlApproval struct {
	Fields              []htmlField
	SignatureResult     string
	SignatureVerifyWith string
	SignatureOrigin     string
}

type htmlDiff struct {
	Baseline      []htmlField
	Current       []htmlField
	Normalization []htmlField
	Counts        []htmlField
	Verdict       []htmlField
	VerdictNote   string
	Rows          []htmlDiffRow
}

type htmlDiffRow struct {
	Kind     string
	ID       string
	Detail   string
	Severity string
	RuleID   string
	Message  string
}

// htmlOmission is one section the page does not show, with the reason and the
// command that shows it. What is left out is named as left out.
type htmlOmission struct {
	What    string
	Why     string
	Command string
}

const htmlLead = "This page is a projection of the bundle named above: it shows what the bundle records, " +
	"in the order the report document has it. It computes no new statement, it evaluates no signature, " +
	"no key trust and no expiry, and it reads no clock. Where it shows such a state, it shows it as a " +
	"quotation from the bundle, with the command that does evaluate it beside it."

const htmlReportCommand = "skillctl trust-freeze report --input <bundle> --output <file.json>"

func htmlPageOf(r Report, opts HTMLOptions) (htmlPage, error) {
	kind := string(r.Input.Kind)
	guidance, ok := htmlGuidanceByKind[r.Input.Kind]
	if !ok {
		return htmlPage{}, fmt.Errorf("%w: kind %q has no guidance", ErrUnsupportedInput, kind)
	}
	page := htmlPage{
		Kind:      kind,
		Title:     "Trust Freeze report: " + kind,
		Lead:      htmlLead,
		Header:    htmlHeaderFields(r),
		Guidance:  guidance,
		Generator: orNotRecorded(opts.Generator),
		Schema:    orNotRecorded(r.SchemaVersion),
	}
	switch r.Input.Kind {
	case trustfreeze.KindCapture, trustfreeze.KindBaseline:
		if r.Capture == nil {
			return htmlPage{}, fmt.Errorf("%w: a %s report without a capture section", ErrUnsupportedInput, kind)
		}
		page.Capture = htmlCaptureOf(r.Capture)
		page.Digests = htmlCaptureDigests(r)
		page.NotShown = htmlCaptureOmissions(r.Capture)
		if r.Input.Kind == trustfreeze.KindBaseline {
			page.Approval = htmlApprovalOf(r)
		}
	case trustfreeze.KindDiff:
		if r.Diff == nil {
			return htmlPage{}, fmt.Errorf("%w: a diff report without a diff section", ErrUnsupportedInput)
		}
		page.Diff = htmlDiffOf(*r.Diff, r.Verdict)
		page.Digests = htmlDiffDigests(r)
		page.NotShown = htmlDiffOmissions(*r.Diff)
	default:
		return htmlPage{}, fmt.Errorf("%w: kind %q", ErrUnsupportedInput, kind)
	}
	return page, nil
}

func htmlHeaderFields(r Report) []htmlField {
	out := []htmlField{
		{"bundle kind", orNotRecorded(string(r.Input.Kind))},
		{"bundle id", orNotRecorded(r.Input.BundleID)},
		{"created at", orNotRecorded(r.Input.CreatedAt)},
	}
	if r.Input.Subject != nil {
		out = append(out,
			htmlField{"subject id", orNotRecorded(r.Input.Subject.ID)},
			htmlField{"subject os family", orNotRecorded(r.Input.Subject.OSFamily)})
	} else {
		out = append(out, htmlField{"subject", notRecorded})
	}
	return out
}

// htmlCaptureDigests is the identity block of a capture or a baseline.
func htmlCaptureDigests(r Report) []htmlDigest {
	verify := "skillctl trust-freeze verify --bundle <bundle>"
	if r.Input.Kind == trustfreeze.KindBaseline {
		verify += " --trusted-key <public key>"
	}
	out := []htmlDigest{{
		Name:    "content digest of this bundle",
		Value:   groupDigest(r.Input.ContentDigest),
		Origin:  "manifest.json, field content_digest",
		Command: verify,
	}}
	if r.Capture != nil {
		out = append(out, htmlDigest{
			Name:    "profile digest of the capture",
			Value:   groupDigest(r.Capture.Meta.Profile.Digest),
			Origin:  "capture.json, field capture.profile.digest",
			Command: verify,
		})
	}
	if r.Input.Kind != trustfreeze.KindBaseline {
		return out
	}
	out = append(out, htmlDigest{
		Name:    "content digest of the approved capture",
		Value:   groupDigest(approvalString(r.Approval, "capture_digest")),
		Origin:  "approval.json, field capture_digest",
		Command: verify,
	}, htmlDigest{
		Name:    "signing key named in the approval",
		Value:   groupDigest(approvalString(r.Approval, "identities", "signing_key_id")),
		Origin:  "approval.json, field identities.signing_key_id. It is the key the approver named when sealing, not a statement about that key.",
		Command: verify,
	})
	return out
}

// htmlDiffDigests is the identity block of a diff: both sides, the rule sets
// and the digest of the diff document itself.
func htmlDiffDigests(r Report) []htmlDigest {
	reproduce := "skillctl trust-freeze diff --baseline <baseline> --current <capture> --trusted-key <public key>"
	verify := "skillctl trust-freeze verify --bundle <bundle>"
	out := []htmlDigest{
		{"content digest of this bundle", groupDigest(r.Input.ContentDigest), "manifest.json, field content_digest", verify},
		{"diff digest", groupDigest(r.Input.DiffDigest), "computed over diff.json by the report (compare.DiffDigest)", reproduce},
	}
	if r.Diff != nil {
		out = append(out,
			htmlDigest{"content digest of the baseline side", groupDigest(r.Diff.Baseline.ContentDigest), "diff.json, field baseline.content_digest", verify},
			htmlDigest{"profile digest of the baseline side", groupDigest(r.Diff.Baseline.Profile.Digest), "diff.json, field baseline.profile.digest", verify},
			htmlDigest{"content digest of the current side", groupDigest(r.Diff.Current.ContentDigest), "diff.json, field current.content_digest", verify},
			htmlDigest{"profile digest of the current side", groupDigest(r.Diff.Current.Profile.Digest), "diff.json, field current.profile.digest", verify},
			htmlDigest{"normalization digest", groupDigest(r.Diff.Normalization.Digest), "diff.json, field normalization.digest", reproduce})
	}
	if r.Verdict != nil {
		out = append(out,
			htmlDigest{"rules digest of the policy", groupDigest(r.Verdict.Policy.RulesDigest), "verdict.json, field policy.rules_digest", reproduce},
			htmlDigest{"diff digest the verdict judged", groupDigest(r.Verdict.DiffDigest), "verdict.json, field diff_digest. The report refuses a verdict that judged another diff.", reproduce})
	}
	return out
}

func htmlCaptureOf(c *CaptureSection) *htmlCapture {
	out := &htmlCapture{
		Meta: []htmlField{
			{"started at", orNotRecorded(c.Meta.StartedAt)},
			{"finished at", orNotRecorded(c.Meta.FinishedAt)},
			{"tool", orNotRecorded(c.Meta.Tool)},
			{"tool version", orNotRecorded(c.Meta.ToolVersion)},
			{"profile", orNotRecorded(c.Meta.Profile.ID)},
			{"profile version", orNotRecorded(c.Meta.Profile.Version)},
			{"actor", orNotRecorded(c.Meta.Actor)},
		},
		Completeness:  orNotRecorded(string(c.Completeness.Status)),
		Required:      c.Completeness.Required,
		ArtifactCount: len(c.Artifacts),
	}
	for _, g := range c.Completeness.Gaps {
		out.Gaps = append(out.Gaps, htmlGap{
			ProbeID: g.ProbeID, Status: orNotRecorded(string(g.Status)), Reason: orNotRecorded(g.Reason),
		})
	}
	for _, p := range c.Probes {
		out.Probes = append(out.Probes, htmlProbe{
			ProbeID: p.ProbeID, Status: orNotRecorded(string(p.Status)), Reason: orNotRecorded(p.Reason),
		})
	}
	if c.Capabilities != nil {
		out.Capabilities = htmlCapabilitiesOf(c.Capabilities)
	}
	return out
}

const htmlCapabilityOrderNote = "The order is the order of the report: the privilege that reaches furthest first, " +
	"then the id. That is a presentation order and no judgement. The diagnostics below belong to the list: " +
	"where the resolver could not read a source, the privileges granted there are not in this document, " +
	"so a short list is not the same as a host that grants little."

func htmlCapabilitiesOf(c *CapabilitiesSection) *htmlCapabilities {
	out := &htmlCapabilities{Resolver: orNotRecorded(c.Resolver), OrderNote: htmlCapabilityOrderNote}
	for _, l := range c.Capabilities {
		out.Lines = append(out.Lines, htmlCapability{
			ID: l.ID, SubjectID: l.SubjectID, Action: l.Action, Resource: l.Resource,
			Effect: l.Effect, Privilege: l.Privilege, Exposure: l.Exposure, Scope: l.Scope,
			State: string(l.State), Confidence: string(l.Confidence),
			Sources:    orNotRecorded(strings.Join(l.Sources, ", ")),
			Attributes: orNotRecorded(joinAttributes(l.Attributes)),
		})
	}
	for _, d := range c.Diagnostics {
		name := d.Code
		if d.Field != "" {
			name += " (" + d.Field + ")"
		}
		out.Diagnostics = append(out.Diagnostics, htmlField{Name: name, Value: orNotRecorded(d.Message)})
	}
	return out
}

const htmlSignatureOrigin = "Quoted from the report projection, which evaluates no signature, no key trust and no expiry. " +
	"Whether the signature holds, whether the key is one you trust and whether the approval has expired are " +
	"decided by the command named beside this row, with a key you bring yourself."

func htmlApprovalOf(r Report) *htmlApproval {
	out := &htmlApproval{
		Fields:          flattenFields("", r.Approval),
		SignatureResult: notRecorded, SignatureVerifyWith: notRecorded,
		SignatureOrigin: htmlSignatureOrigin,
	}
	if r.Signature != nil {
		out.SignatureResult = orNotRecorded(r.Signature.Result)
		out.SignatureVerifyWith = orNotRecorded(r.Signature.VerifyWith)
	}
	return out
}

func htmlDiffOf(d compare.Diff, v *policy.Verdict) *htmlDiff {
	out := &htmlDiff{
		Baseline:      htmlInputRef(d.Baseline),
		Current:       htmlInputRef(d.Current),
		Normalization: []htmlField{{"normalization rule set", orNotRecorded(d.Normalization.ID)}, {"subject mismatch allowed", strconv.FormatBool(d.AllowSubjectMismatch)}},
	}
	for _, kind := range sortedKeys(d.Counts) {
		out.Counts = append(out.Counts, htmlField{Name: kind, Value: strconv.Itoa(d.Counts[kind])})
	}
	if v == nil {
		out.VerdictNote = "This diff bundle carries no verdict document, so no severity was assigned to any entry below."
	} else {
		highest := string(v.HighestSeverity)
		if highest == "" {
			highest = "none"
		}
		out.Verdict = []htmlField{
			{"policy", orNotRecorded(v.Policy.ID)},
			{"highest severity", highest},
			{"fail on", orNotRecorded(string(v.FailOn))},
			{"threshold exceeded", strconv.FormatBool(v.ThresholdExceeded)},
		}
		for _, sev := range sortedKeys(v.Counts) {
			out.Verdict = append(out.Verdict, htmlField{Name: "findings at severity " + sev, Value: strconv.Itoa(v.Counts[sev])})
		}
		out.VerdictNote = "The severity of an entry comes from the policy named above and from nowhere else. " +
			"A threshold that was exceeded says that the highest severity reached the configured level; it says nothing about who changed what, or whether the change was allowed."
	}
	for i, c := range d.Changes {
		row := htmlDiffRow{
			Kind: string(c.Kind), ID: orNotRecorded(diffEntryID(c)), Detail: orNotRecorded(diffRowDetail(c)),
			Severity: notRecorded, RuleID: notRecorded, Message: notRecorded,
		}
		if v != nil && i < len(v.Findings) {
			f := v.Findings[i]
			row.Severity, row.RuleID, row.Message = string(f.Severity), orNotRecorded(f.RuleID), orNotRecorded(f.Message)
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}

func htmlInputRef(ref compare.InputRef) []htmlField {
	return []htmlField{
		{"kind", orNotRecorded(string(ref.Kind))},
		{"bundle id", orNotRecorded(ref.BundleID)},
		{"subject id", orNotRecorded(ref.Subject.ID)},
		{"profile", orNotRecorded(ref.Profile.ID)},
		{"profile version", orNotRecorded(ref.Profile.Version)},
	}
}

// diffEntryID names what a change is about: an artifact, a capability, a probe
// or the subject.
func diffEntryID(c compare.Change) string {
	switch {
	case c.ArtifactID != "":
		return c.ArtifactID
	case c.CapabilityID != "":
		return c.CapabilityID
	case c.ProbeID != "":
		return c.ProbeID
	case c.BeforeSubjectID != "" || c.AfterSubjectID != "":
		return c.BeforeSubjectID + " to " + c.AfterSubjectID
	}
	return ""
}

// diffRowDetail composes what the entry records, without the attribute digests
// of either side: those are in the report document, and the page says so.
func diffRowDetail(c compare.Change) string {
	var parts []string
	add := func(label string, values []string) {
		if len(values) > 0 {
			parts = append(parts, label+": "+strings.Join(values, ", "))
		}
	}
	add("changed fields", c.ChangedFields)
	add("changed attributes", c.ChangedAttributes)
	add("attributes no longer observed", c.UnobservedAttributes)
	add("probes blind in the baseline", c.BaselineGapProbes)
	add("probes with thinner baseline coverage", c.CoverageCaveatProbes)
	pair := func(label, before, after string) {
		if before != "" || after != "" {
			parts = append(parts, fmt.Sprintf("%s before: %s, after: %s", label, orNotRecorded(before), orNotRecorded(after)))
		}
	}
	pair("privilege", c.BeforePrivilege, c.AfterPrivilege)
	pair("state", string(c.BeforeState), string(c.AfterState))
	pair("confidence", string(c.BeforeConfidence), string(c.AfterConfidence))
	pair("probe status", string(c.BeforeStatus), string(c.AfterStatus))
	if c.ArtifactType != "" {
		parts = append(parts, "artifact type: "+c.ArtifactType)
	}
	if c.ArtifactID != "" && c.ProbeID != "" {
		parts = append(parts, "probe: "+c.ProbeID)
	}
	if g := c.Gap; g != nil {
		gap := "gap cause: " + orNotRecorded(g.Cause)
		if g.Status != "" {
			gap += ", probe status: " + string(g.Status)
		}
		if g.Reason != "" {
			gap += ", reason: " + g.Reason
		}
		gap += ", required: " + strconv.FormatBool(g.Required)
		parts = append(parts, gap)
	}
	if c.SubjectMismatchAllowed {
		parts = append(parts, "subject mismatch allowed: true")
	}
	return strings.Join(parts, "; ")
}

func htmlCaptureOmissions(c *CaptureSection) []htmlOmission {
	out := []htmlOmission{{
		What: fmt.Sprintf("The artifacts of this capture: %d entries.", len(c.Artifacts)),
		Why: "One row per artifact is a stack of paper and not a printout, and the list carries the host name, " +
			"every local account, every listening address and the fingerprint of every authorized key. " +
			"The count is on this page so that nothing is hidden, and the report document has every entry.",
		Command: htmlReportCommand,
	}, {
		What: fmt.Sprintf("The full result of each probe: %d documents, with every command a probe ran and the state it normalized.", len(c.ProbeResults)),
		Why: "The table above names every probe with its status and its reason in full; the raw results repeat the " +
			"artifacts and add the invocation records.",
		Command: htmlReportCommand,
	}}
	return out
}

func htmlDiffOmissions(d compare.Diff) []htmlOmission {
	return []htmlOmission{{
		What: fmt.Sprintf("The attribute digests of both sides of each of the %d entries (before_digest, after_digest).", len(d.Changes)),
		Why: "An attribute value never appears in a diff; the digests stand for the normalized attribute maps. " +
			"They are machine material, and they are in the report document.",
		Command: htmlReportCommand,
	}}
}

// --- small helpers -----------------------------------------------------------

// groupDigest renders a digest for the eye: the algorithm prefix, then the
// value in groups of eight characters. Removing the spaces gives the value
// back unchanged, which a test measures.
func groupDigest(v string) string {
	if v == "" {
		return notRecorded
	}
	prefix, rest := "", v
	if i := strings.Index(v, ":"); i >= 0 {
		prefix, rest = v[:i+1], v[i+1:]
	}
	var groups []string
	for len(rest) > 8 {
		groups = append(groups, rest[:8])
		rest = rest[8:]
	}
	if rest != "" {
		groups = append(groups, rest)
	}
	return prefix + strings.Join(groups, " ")
}

// orNotRecorded renders an empty value as n/a, so an empty cell is never read
// as a value of its own.
func orNotRecorded(s string) string {
	if s == "" {
		return notRecorded
	}
	return s
}

// joinAttributes renders an attribute map as key=value pairs, sorted by key.
func joinAttributes(m map[string]string) string {
	out := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		out = append(out, k+"="+m[k])
	}
	return strings.Join(out, ", ")
}

// sortedKeys returns the keys of a map in sorted order, so a page never
// depends on map iteration order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// approvalString reads a string from the projected approval object along a
// path of keys, and returns "" when the path is not there.
func approvalString(approval map[string]any, path ...string) string {
	var cur any = approval
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[key]
		if !ok {
			return ""
		}
	}
	s, _ := cur.(string)
	return s
}

// flattenFields renders a generic JSON object as labelled rows with dotted
// paths, sorted, so an approval is readable without a JSON reader.
func flattenFields(prefix string, v any) []htmlField {
	switch node := v.(type) {
	case map[string]any:
		var out []htmlField
		for _, k := range sortedKeys(node) {
			out = append(out, flattenFields(joinPath(prefix, k), node[k])...)
		}
		return out
	case []any:
		var out []htmlField
		for i, e := range node {
			out = append(out, flattenFields(fmt.Sprintf("%s[%d]", prefix, i), e)...)
		}
		return out
	}
	return []htmlField{{Name: orNotRecorded(prefix), Value: scalarText(v)}}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// scalarText renders one scalar of a generic JSON tree.
func scalarText(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return orNotRecorded(t)
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}
