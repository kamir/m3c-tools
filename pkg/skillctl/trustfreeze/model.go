package trustfreeze

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The model contains no floating-point field anywhere (SPEC-0466 R5): counts
// and sizes are int64, durations are int64 milliseconds, times are strings
// produced by FormatTime.

// Subject identifies the observed device. ID comes from SubjectID; OSFamily is
// the runtime.GOOS value of the observed host ("linux", "darwin", "windows").
// The hostname is not part of the subject; it lives only in the device/host
// artifact with sensitivity internal (SPEC-0466 R4).
type Subject struct {
	ID       string `json:"id"`
	OSFamily string `json:"os_family"`
}

// Provenance says how an artifact was obtained (SPEC-0466 R3).
type Provenance struct {
	// Method is how the value was read, for example "command", "file",
	// "registry" or "runtime".
	Method     string     `json:"method"`
	Confidence Confidence `json:"confidence"`
	// Sources name the inputs, for example "command:sw_vers" or
	// "file:/etc/os-release". No user-specific absolute path.
	Sources     []string `json:"sources,omitempty"`
	ObservedAt  string   `json:"observed_at"`
	ToolVersion string   `json:"tool_version,omitempty"`
}

// Artifact is one normalized piece of observed state (SPEC-0466 R3). IDs are
// stable and never contain absolute or user-specific paths (see
// ValidateArtifactID). Attributes are strings only, so the canonical form has
// no floating-point values and sorts deterministically.
type Artifact struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Scope       string            `json:"scope"`
	Source      string            `json:"source"`
	State       EvidenceState     `json:"state"`
	Digest      string            `json:"digest"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Provenance  Provenance        `json:"provenance"`
	Sensitivity Sensitivity       `json:"sensitivity"`
}

// Capability is a resolved "who can do what to which resource" statement
// (SPEC-0468 R7). Every capability references its sources.
type Capability struct {
	ID         string        `json:"id"`
	SubjectID  string        `json:"subject_id"`
	Action     string        `json:"action"`
	Resource   string        `json:"resource"`
	Effect     string        `json:"effect"`
	State      EvidenceState `json:"state"`
	Scope      string        `json:"scope"`
	Exposure   string        `json:"exposure,omitempty"`
	Privilege  string        `json:"privilege,omitempty"`
	Sources    []string      `json:"sources"`
	Confidence Confidence    `json:"confidence"`
}

// Finding is one judged observation. Compare produces changes; policy assigns
// the severity.
type Finding struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Severity   Severity `json:"severity"`
	ArtifactID string   `json:"artifact_id,omitempty"`
	ProbeID    string   `json:"probe_id,omitempty"`
	RuleID     string   `json:"rule_id,omitempty"`
	Message    string   `json:"message"`
}

// ToolInvocation records one command a probe ran (SPEC-0467 R8). Every field
// that carries arguments or output has passed the redactor before it gets here.
type ToolInvocation struct {
	// Name is the executable as requested, for example "sw_vers".
	Name string `json:"name"`
	// Path is the resolved executable path; user-specific paths are redacted.
	Path            string   `json:"path,omitempty"`
	Args            []string `json:"args"`
	ExitCode        int      `json:"exit_code"`
	DurationMS      int64    `json:"duration_ms"`
	TimedOut        bool     `json:"timed_out,omitempty"`
	StdoutBytes     int64    `json:"stdout_bytes"`
	StderrBytes     int64    `json:"stderr_bytes"`
	StdoutTruncated bool     `json:"stdout_truncated,omitempty"`
	StderrTruncated bool     `json:"stderr_truncated,omitempty"`
	ToolVersion     string   `json:"tool_version,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// EvidenceRef points at one redacted raw evidence file inside the bundle.
// Writer.WriteEvidence returns it filled in.
type EvidenceRef struct {
	// Path is the canonical bundle path, evidence/<probe-id>/<name>.
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Source names what the bytes are, for example "stdout:sw_vers".
	Source    string `json:"source,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Diagnostic is a machine-readable note attached to a probe result.
type Diagnostic struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
}

// Diagnostic codes and reasons shared across packages.
const (
	// DiagRedactionFailed: evidence was dropped because redaction failed
	// (fail-closed, SPEC-0467 R5).
	DiagRedactionFailed = "redaction_failed"
	// DiagFieldMissing: an expected field was not present in the tool output.
	DiagFieldMissing = "field_missing"
	// DiagOutputTruncated: a byte cap cut the output.
	DiagOutputTruncated = "output_truncated"
	// ReasonNotImplemented: the probe does not exist in this build yet.
	ReasonNotImplemented = "not_implemented"
	// ReasonExcludedByOperator: the probe is part of the profile but was not
	// run, because the operator selected probes (--probe, --exclude-probe).
	// It is recorded with status unsupported, so the capture shows every
	// probe of its profile and compare reports the gap (SPEC-0469 section
	// 4.2).
	ReasonExcludedByOperator = "excluded_by_operator"
)

// ProbeError is the error class and message of a failed probe.
type ProbeError struct {
	// Class is a stable machine-readable class, for example "timeout",
	// "permission_denied", "tool_missing", "panic" or "limit_exceeded".
	Class   string `json:"class"`
	Message string `json:"message,omitempty"`
}

// Error implements error.
func (e *ProbeError) Error() string {
	if e.Message == "" {
		return e.Class
	}
	return e.Class + ": " + e.Message
}

// SupportRecord is the outcome of the probe's Support check. When Available
// is false, the ProbeResult status says why (unsupported, unavailable or
// not_applicable) and Reason gives the detail.
type SupportRecord struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// ProbeResult is the persisted outcome of one probe (SPEC-0466 R6, SPEC-0467),
// written to probes/<probe-id>.json.
type ProbeResult struct {
	ProbeID      string      `json:"probe_id"`
	ProbeVersion string      `json:"probe_version"`
	Status       ProbeStatus `json:"status"`
	// Reason explains a non-captured status. A not_applicable result counts
	// toward completeness only with a non-empty Reason.
	Reason          string           `json:"reason,omitempty"`
	Support         SupportRecord    `json:"support"`
	StartedAt       string           `json:"started_at"`
	DurationMS      int64            `json:"duration_ms"`
	Privilege       Privilege        `json:"privilege"`
	Tools           []ToolInvocation `json:"tools,omitempty"`
	RawEvidence     []EvidenceRef    `json:"raw_evidence,omitempty"`
	NormalizedState []Artifact       `json:"normalized_state,omitempty"`
	Warnings        []Diagnostic     `json:"warnings,omitempty"`
	Error           *ProbeError      `json:"error,omitempty"`
}

// ProfileRef identifies the profile a capture ran with; Digest is
// "sha256:<hex>" of the exact profile bytes.
type ProfileRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// CaptureMeta is the "capture" object of capture.json.
type CaptureMeta struct {
	StartedAt   string     `json:"started_at"`
	FinishedAt  string     `json:"finished_at"`
	Tool        string     `json:"tool"`
	ToolVersion string     `json:"tool_version"`
	Profile     ProfileRef `json:"profile"`
	// Actor identifies who ran the capture, when known (SPEC-0470 TF05-R7).
	Actor string `json:"actor,omitempty"`
}

// CaptureTool is the value of CaptureMeta.Tool.
const CaptureTool = "skillctl"

// ProbeSummary is one entry of the probes list in capture.json.
type ProbeSummary struct {
	ProbeID string      `json:"probe_id"`
	Status  ProbeStatus `json:"status"`
	Reason  string      `json:"reason,omitempty"`
}

// CompletenessGap names one required probe that keeps a capture incomplete.
type CompletenessGap struct {
	ProbeID string `json:"probe_id"`
	// Status is the recorded status, empty when there is no result at all.
	Status ProbeStatus `json:"status,omitempty"`
	// Reason is one of the Gap* constants.
	Reason string `json:"reason"`
}

// Gap reasons.
const (
	GapNoResult              = "no_result"
	GapDuplicateResult       = "duplicate_result"
	GapNotCaptured           = "not_captured"
	GapNotApplicableNoReason = "not_applicable_without_reason"
	GapInvalidStatus         = "invalid_status"
	// GapNotApplicable is a diff cause only: the probe is not_applicable with
	// a reason. Completeness counts such a probe as satisfied, so a capture
	// never lists it as a gap; compare keeps it visible as its own collection
	// gap (SPEC-0469 section 4.2).
	GapNotApplicable = "not_applicable"
)

// GapReasons returns every gap reason, GapNotApplicable included, sorted.
func GapReasons() []string {
	return []string{GapDuplicateResult, GapInvalidStatus, GapNoResult, GapNotApplicable, GapNotApplicableNoReason, GapNotCaptured}
}

// Completeness is computed by ComputeCompleteness. A reader recomputes it and
// rejects a file whose declared value differs (ReadBundle).
type Completeness struct {
	Status   CompletenessStatus `json:"status"`
	Required []string           `json:"required"`
	Gaps     []CompletenessGap  `json:"gaps"`
}

// CaptureDoc is capture.json (SPEC-0466 R2). Kind is always KindCapture, also
// inside a baseline bundle, which carries a byte-identical copy.
type CaptureDoc struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          Kind           `json:"kind"`
	Capture       CaptureMeta    `json:"capture"`
	Subject       Subject        `json:"subject"`
	Completeness  Completeness   `json:"completeness"`
	Probes        []ProbeSummary `json:"probes"`
}

// StateDoc is state/device.json: the normalized device artifacts, sorted by ID.
type StateDoc struct {
	Artifacts []Artifact `json:"artifacts"`
}

// SortArtifacts sorts artifacts by ID in byte order.
func SortArtifacts(a []Artifact) {
	sort.SliceStable(a, func(i, j int) bool { return a[i].ID < a[j].ID })
}

// ErrInvalidID is wrapped by ValidateArtifactID and ValidateProbeID.
var ErrInvalidID = errors.New("trustfreeze: invalid id")

// ValidateArtifactID rejects ids that are empty, contain whitespace, control
// characters, a backslash or "~", start with "/", contain an empty, "." or ".."
// segment, or have a drive-letter segment such as "C:". Artifact ids must never
// carry absolute or user-specific paths (SPEC-0466 R4).
func ValidateArtifactID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty artifact id", ErrInvalidID)
	}
	for _, r := range id {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("%w: artifact id %q has whitespace or a control character", ErrInvalidID, id)
		}
		if r == '\\' || r == '~' {
			return fmt.Errorf("%w: artifact id %q has a %q", ErrInvalidID, id, r)
		}
	}
	if strings.HasPrefix(id, "/") {
		return fmt.Errorf("%w: artifact id %q is an absolute path", ErrInvalidID, id)
	}
	for _, seg := range strings.Split(id, "/") {
		switch {
		case seg == "":
			return fmt.Errorf("%w: artifact id %q has an empty segment", ErrInvalidID, id)
		case seg == "." || seg == "..":
			return fmt.Errorf("%w: artifact id %q has a %q segment", ErrInvalidID, id, seg)
		case isDriveSegment(seg):
			return fmt.Errorf("%w: artifact id %q has a drive letter segment", ErrInvalidID, id)
		}
	}
	return nil
}

// ValidateProbeID accepts ids like "common.identity": lowercase ASCII letters,
// digits, ".", "_" and "-", starting with a letter, with no empty dot segment.
// A valid probe id is also a valid file name on every supported OS.
func ValidateProbeID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty probe id", ErrInvalidID)
	}
	if id[0] < 'a' || id[0] > 'z' {
		return fmt.Errorf("%w: probe id %q must start with a lowercase letter", ErrInvalidID, id)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		case c == '.':
			if i == len(id)-1 || id[i+1] == '.' {
				return fmt.Errorf("%w: probe id %q has an empty dot segment", ErrInvalidID, id)
			}
		default:
			return fmt.Errorf("%w: probe id %q has character %q", ErrInvalidID, id, c)
		}
	}
	return nil
}

// ProbeResultPath returns "probes/<probe-id>.json".
func ProbeResultPath(probeID string) (string, error) {
	if err := ValidateProbeID(probeID); err != nil {
		return "", err
	}
	return ProbesDir + "/" + probeID + ".json", nil
}

// EvidencePath returns "evidence/<probe-id>/<name>" after checking that name
// is a single canonical path segment.
func EvidencePath(probeID, name string) (string, error) {
	if err := ValidateProbeID(probeID); err != nil {
		return "", err
	}
	p := EvidenceDir + "/" + probeID + "/" + name
	c, err := CanonicalPath(p)
	if err != nil {
		return "", err
	}
	if c != p || strings.Contains(name, "/") {
		return "", fmt.Errorf("%w: evidence name %q is not a single canonical segment", ErrBadPath, name)
	}
	return p, nil
}

// ComputeArtifactDigest returns "sha256:<hex>" over the canonical JSON of the
// artifact's identity and attributes (id, type, scope, attributes). State,
// provenance and sensitivity are excluded on purpose: a change of those is
// reported by compare as its own change kind, not as a content change.
func ComputeArtifactDigest(a Artifact) (string, error) {
	attrs := a.Attributes
	if attrs == nil {
		attrs = map[string]string{}
	}
	b, err := MarshalCanonical(struct {
		ID         string            `json:"id"`
		Type       string            `json:"type"`
		Scope      string            `json:"scope"`
		Attributes map[string]string `json:"attributes"`
	}{a.ID, a.Type, a.Scope, attrs})
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}
