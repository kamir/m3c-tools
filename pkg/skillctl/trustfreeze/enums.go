package trustfreeze

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidEnum is wrapped by every strict enum parse and marshal failure.
var ErrInvalidEnum = errors.New("trustfreeze: invalid enum value")

func member[T ~string](v T, values []T) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

func parseEnum[T ~string](name, s string, values []T) (T, error) {
	v := T(s)
	if !member(v, values) {
		return "", fmt.Errorf("%w: %s %q", ErrInvalidEnum, name, s)
	}
	return v, nil
}

func marshalEnum[T ~string](name string, v T, values []T) ([]byte, error) {
	if !member(v, values) {
		return nil, fmt.Errorf("%w: refusing to write %s %q", ErrInvalidEnum, name, string(v))
	}
	return []byte(v), nil
}

// jsonEnumString decodes b as a JSON string. null, numbers, booleans, objects
// and arrays are rejected: a missing status must never decode as a zero value.
func jsonEnumString(name string, b []byte) (string, error) {
	if len(b) == 0 || b[0] != '"' {
		return "", fmt.Errorf("%w: %s must be a JSON string, got %s", ErrInvalidEnum, name, truncateForError(b))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrInvalidEnum, name, err)
	}
	return s, nil
}

func truncateForError(b []byte) string {
	const maxLen = 32
	if len(b) > maxLen {
		return string(b[:maxLen]) + "..."
	}
	return string(b)
}

// ProbeStatus is the outcome of one probe (SPEC-0466 R6, SPEC-0471 TF06-R2).
// The values are not interchangeable: not_applicable (the OS has no such
// feature), unavailable (the tool is missing) and permission_denied (blocked by
// privilege) mean different things.
type ProbeStatus string

// Probe statuses.
const (
	StatusCaptured         ProbeStatus = "captured"
	StatusPartial          ProbeStatus = "partial"
	StatusUnsupported      ProbeStatus = "unsupported"
	StatusUnavailable      ProbeStatus = "unavailable"
	StatusPermissionDenied ProbeStatus = "permission_denied"
	StatusTimeout          ProbeStatus = "timeout"
	StatusFailed           ProbeStatus = "failed"
	StatusNotApplicable    ProbeStatus = "not_applicable"
)

var probeStatusValues = []ProbeStatus{
	StatusCaptured, StatusPartial, StatusUnsupported, StatusUnavailable,
	StatusPermissionDenied, StatusTimeout, StatusFailed, StatusNotApplicable,
}

// ProbeStatuses returns every probe status in declaration order.
func ProbeStatuses() []ProbeStatus { return append([]ProbeStatus(nil), probeStatusValues...) }

// Valid reports whether s is a known probe status.
func (s ProbeStatus) Valid() bool { return member(s, probeStatusValues) }

// ParseProbeStatus parses a probe status strictly (case-sensitive, no trimming).
func ParseProbeStatus(s string) (ProbeStatus, error) {
	return parseEnum("probe status", s, probeStatusValues)
}

// MarshalText rejects an unknown status.
func (s ProbeStatus) MarshalText() ([]byte, error) {
	return marshalEnum("probe status", s, probeStatusValues)
}

// UnmarshalText parses a probe status strictly.
func (s *ProbeStatus) UnmarshalText(b []byte) error {
	v, err := ParseProbeStatus(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known status.
func (s *ProbeStatus) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("probe status", b)
	if err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}

// EvidenceState says how strongly an artifact is known to be in effect
// (SPEC-0468 R5). declared or resolved is never reported as observed.
type EvidenceState string

// Evidence states.
const (
	StateDeclared EvidenceState = "declared"
	StateResolved EvidenceState = "resolved"
	StateObserved EvidenceState = "observed"
	StateInferred EvidenceState = "inferred"
	StateUnknown  EvidenceState = "unknown"
)

var evidenceStateValues = []EvidenceState{StateDeclared, StateResolved, StateObserved, StateInferred, StateUnknown}

// EvidenceStates returns every evidence state in declaration order.
func EvidenceStates() []EvidenceState {
	return append([]EvidenceState(nil), evidenceStateValues...)
}

// Valid reports whether s is a known evidence state.
func (s EvidenceState) Valid() bool { return member(s, evidenceStateValues) }

// ParseEvidenceState parses an evidence state strictly.
func ParseEvidenceState(s string) (EvidenceState, error) {
	return parseEnum("evidence state", s, evidenceStateValues)
}

// MarshalText rejects an unknown state.
func (s EvidenceState) MarshalText() ([]byte, error) {
	return marshalEnum("evidence state", s, evidenceStateValues)
}

// UnmarshalText parses an evidence state strictly.
func (s *EvidenceState) UnmarshalText(b []byte) error {
	v, err := ParseEvidenceState(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known state.
func (s *EvidenceState) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("evidence state", b)
	if err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}

// Confidence grades provenance: proven (authoritative output, file or
// signature), corroborated (at least two distinguishable sources), reported
// (declared documentation or user statement), unknown.
type Confidence string

// Confidence levels.
const (
	ConfidenceProven       Confidence = "proven"
	ConfidenceCorroborated Confidence = "corroborated"
	ConfidenceReported     Confidence = "reported"
	ConfidenceUnknown      Confidence = "unknown"
)

var confidenceValues = []Confidence{ConfidenceProven, ConfidenceCorroborated, ConfidenceReported, ConfidenceUnknown}

// Confidences returns every confidence level in declaration order.
func Confidences() []Confidence { return append([]Confidence(nil), confidenceValues...) }

// Valid reports whether c is a known confidence level.
func (c Confidence) Valid() bool { return member(c, confidenceValues) }

// ParseConfidence parses a confidence level strictly.
func ParseConfidence(s string) (Confidence, error) {
	return parseEnum("confidence", s, confidenceValues)
}

// MarshalText rejects an unknown confidence level.
func (c Confidence) MarshalText() ([]byte, error) {
	return marshalEnum("confidence", c, confidenceValues)
}

// UnmarshalText parses a confidence level strictly.
func (c *Confidence) UnmarshalText(b []byte) error {
	v, err := ParseConfidence(string(b))
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known confidence level.
func (c *Confidence) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("confidence", b)
	if err != nil {
		return err
	}
	return c.UnmarshalText([]byte(str))
}

// Severity grades a finding. Rank orders the values; the highest wins
// (SPEC-0469 R6).
type Severity string

// Severities, lowest first.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityValues = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Severities returns every severity, lowest first.
func Severities() []Severity { return append([]Severity(nil), severityValues...) }

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return member(s, severityValues) }

// Rank returns 1 (info) to 5 (critical), or 0 for an unknown value.
func (s Severity) Rank() int {
	for i, v := range severityValues {
		if v == s {
			return i + 1
		}
	}
	return 0
}

// ParseSeverity parses a severity strictly.
func ParseSeverity(s string) (Severity, error) {
	return parseEnum("severity", s, severityValues)
}

// MarshalText rejects an unknown severity.
func (s Severity) MarshalText() ([]byte, error) {
	return marshalEnum("severity", s, severityValues)
}

// UnmarshalText parses a severity strictly.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known severity.
func (s *Severity) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("severity", b)
	if err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}

// Sensitivity classifies an artifact for later disclosure decisions. Secret
// values are never stored at all (SPEC-0467 R5), so there is no "secret"
// level. The hostname is internal (SPEC-0466 R4).
type Sensitivity string

// Sensitivity levels.
const (
	SensitivityPublic       Sensitivity = "public"
	SensitivityInternal     Sensitivity = "internal"
	SensitivityConfidential Sensitivity = "confidential"
)

var sensitivityValues = []Sensitivity{SensitivityPublic, SensitivityInternal, SensitivityConfidential}

// Valid reports whether s is a known sensitivity level.
func (s Sensitivity) Valid() bool { return member(s, sensitivityValues) }

// ParseSensitivity parses a sensitivity level strictly.
func ParseSensitivity(s string) (Sensitivity, error) {
	return parseEnum("sensitivity", s, sensitivityValues)
}

// MarshalText rejects an unknown sensitivity level.
func (s Sensitivity) MarshalText() ([]byte, error) {
	return marshalEnum("sensitivity", s, sensitivityValues)
}

// UnmarshalText parses a sensitivity level strictly.
func (s *Sensitivity) UnmarshalText(b []byte) error {
	v, err := ParseSensitivity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known sensitivity level.
func (s *Sensitivity) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("sensitivity", b)
	if err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}

// Privilege is the privilege a probe ran with. Trust Freeze never elevates
// (SPEC-0467 R6); the value records what the process had.
type Privilege string

// Privilege levels.
const (
	PrivilegeUser     Privilege = "user"
	PrivilegeElevated Privilege = "elevated"
)

var privilegeValues = []Privilege{PrivilegeUser, PrivilegeElevated}

// Valid reports whether p is a known privilege level.
func (p Privilege) Valid() bool { return member(p, privilegeValues) }

// ParsePrivilege parses a privilege level strictly.
func ParsePrivilege(s string) (Privilege, error) {
	return parseEnum("privilege", s, privilegeValues)
}

// MarshalText rejects an unknown privilege level.
func (p Privilege) MarshalText() ([]byte, error) {
	return marshalEnum("privilege", p, privilegeValues)
}

// UnmarshalText parses a privilege level strictly.
func (p *Privilege) UnmarshalText(b []byte) error {
	v, err := ParsePrivilege(string(b))
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known privilege level.
func (p *Privilege) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("privilege", b)
	if err != nil {
		return err
	}
	return p.UnmarshalText([]byte(str))
}

// CompletenessStatus is complete or incomplete. It is always recomputed from
// the probe results (see ComputeCompleteness), never taken from a file as truth.
type CompletenessStatus string

// Completeness statuses.
const (
	CompletenessComplete   CompletenessStatus = "complete"
	CompletenessIncomplete CompletenessStatus = "incomplete"
)

var completenessValues = []CompletenessStatus{CompletenessComplete, CompletenessIncomplete}

// Valid reports whether s is a known completeness status.
func (s CompletenessStatus) Valid() bool { return member(s, completenessValues) }

// ParseCompletenessStatus parses a completeness status strictly.
func ParseCompletenessStatus(s string) (CompletenessStatus, error) {
	return parseEnum("completeness status", s, completenessValues)
}

// MarshalText rejects an unknown completeness status.
func (s CompletenessStatus) MarshalText() ([]byte, error) {
	return marshalEnum("completeness status", s, completenessValues)
}

// UnmarshalText parses a completeness status strictly.
func (s *CompletenessStatus) UnmarshalText(b []byte) error {
	v, err := ParseCompletenessStatus(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known completeness status.
func (s *CompletenessStatus) UnmarshalJSON(b []byte) error {
	str, err := jsonEnumString("completeness status", b)
	if err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}
