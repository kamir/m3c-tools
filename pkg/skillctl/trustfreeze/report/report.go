// Package report projects Trust Freeze results onto one deterministic JSON
// document (SPEC-0469 section 4.7, SPEC-0470): a capture, a baseline, or a
// diff with its verdict. It is a pure projection and decides nothing of its
// own: severities and the threshold come from the verdict, integrity from the
// core reader. It never evaluates a baseline signature, key trust or expiry
// (this package never imports seal, and reads no clock), so the report of an
// unchanged bundle never changes over time; a baseline report says
// "not_evaluated" and names verify, which does evaluate them.
//
// Markdown and SARIF are not implemented in this version.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/policy"
)

// SchemaReport is the schema id of a report document.
const SchemaReport = "trust-freeze/report/v1"

// SignatureNotEvaluated is the signature result of every baseline report:
// report projects, verify evaluates.
const SignatureNotEvaluated = "not_evaluated"

// SignatureVerifyWith names the command that evaluates signature, key trust
// and expiry of a baseline.
const SignatureVerifyWith = "skillctl trust-freeze verify"

// Errors.
var (
	// ErrNotVerified: the input bundle did not pass its integrity check.
	ErrNotVerified = errors.New("report: input bundle is not verified")
	// ErrUnsupportedInput: the input is not a capture, baseline or diff the
	// report can project.
	ErrUnsupportedInput = errors.New("report: unsupported input")
	// ErrInconsistent: parts of the input contradict each other, for example
	// a verdict that judged a different diff.
	ErrInconsistent = errors.New("report: inconsistent input")
)

// Report is the report document. Exactly one of Capture or Diff is set.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	Input         Input           `json:"input"`
	Capture       *CaptureSection `json:"capture,omitempty"`
	// Approval is approval.json of a baseline, projected key by key (keys
	// sorted). Its validity is decided by verify, not here.
	Approval  map[string]any   `json:"approval,omitempty"`
	Signature *SignatureStatus `json:"signature,omitempty"`
	Diff      *compare.Diff    `json:"diff,omitempty"`
	Verdict   *policy.Verdict  `json:"verdict,omitempty"`
}

// Input identifies what the report projects. A bundle input has passed the
// core integrity check (manifest, sizes, digests, layout); nothing more is
// implied.
type Input struct {
	Kind          trustfreeze.Kind     `json:"kind"`
	BundleID      string               `json:"bundle_id,omitempty"`
	ContentDigest string               `json:"content_digest,omitempty"`
	CreatedAt     string               `json:"created_at,omitempty"`
	Subject       *trustfreeze.Subject `json:"subject,omitempty"`
	// DiffDigest is set for a diff input (compare.DiffDigest).
	DiffDigest string `json:"diff_digest,omitempty"`
}

// CaptureSection is the capture of a capture or baseline bundle.
type CaptureSection struct {
	Meta         trustfreeze.CaptureMeta    `json:"meta"`
	Completeness trustfreeze.Completeness   `json:"completeness"`
	Probes       []trustfreeze.ProbeSummary `json:"probes"`
	// ProbeResults are the manifested probes/<probe-id>.json files, sorted by
	// probe id.
	ProbeResults []trustfreeze.ProbeResult `json:"probe_results"`
	// Artifacts are state/device.json, sorted by id.
	Artifacts []trustfreeze.Artifact `json:"artifacts"`
}

// SignatureStatus is the signature section of a baseline report. Result is
// always SignatureNotEvaluated and VerifyWith SignatureVerifyWith: whether the
// signature is valid, the key trusted and the approval unexpired depends on
// trust material and a clock, which a projection does not have.
type SignatureStatus struct {
	Result     string `json:"result"`
	VerifyWith string `json:"verify_with"`
}

// FromBundle projects a verified capture, baseline or diff bundle. A diff
// bundle must manifest compare.DiffFile and may manifest policy.VerdictFile.
func FromBundle(b *trustfreeze.Bundle) (Report, error) {
	if b == nil || !b.Integrity.OK {
		return Report{}, ErrNotVerified
	}
	m := b.Manifest
	subject := m.Subject
	r := Report{
		SchemaVersion: SchemaReport,
		Input: Input{
			Kind:          m.Kind,
			BundleID:      m.BundleID,
			ContentDigest: m.ContentDigest,
			CreatedAt:     m.CreatedAt,
			Subject:       &subject,
		},
	}
	switch m.Kind {
	case trustfreeze.KindCapture, trustfreeze.KindBaseline:
		cs, err := captureSection(b)
		if err != nil {
			return Report{}, err
		}
		r.Capture = cs
		if m.Kind == trustfreeze.KindBaseline {
			ap, err := readApproval(b)
			if err != nil {
				return Report{}, err
			}
			r.Approval = ap
			r.Signature = &SignatureStatus{Result: SignatureNotEvaluated, VerifyWith: SignatureVerifyWith}
		}
	case trustfreeze.KindDiff:
		raw, err := b.ReadFile(compare.DiffFile)
		if err != nil {
			return Report{}, fmt.Errorf("%w: diff bundle: %w", ErrUnsupportedInput, err)
		}
		d, err := compare.ParseDiff(raw)
		if err != nil {
			return Report{}, err
		}
		var v *policy.Verdict
		if b.Has(policy.VerdictFile) {
			vraw, err := b.ReadFile(policy.VerdictFile)
			if err != nil {
				return Report{}, err
			}
			pv, err := policy.ParseVerdict(vraw)
			if err != nil {
				return Report{}, err
			}
			v = &pv
		}
		if err := setDiff(&r, d, v); err != nil {
			return Report{}, err
		}
	default:
		return Report{}, fmt.Errorf("%w: kind %q", ErrUnsupportedInput, m.Kind)
	}
	return r, nil
}

// FromDiff projects a diff and, when not nil, its verdict. The verdict must
// have judged exactly this diff.
func FromDiff(d compare.Diff, v *policy.Verdict) (Report, error) {
	r := Report{SchemaVersion: SchemaReport, Input: Input{Kind: trustfreeze.KindDiff}}
	if err := setDiff(&r, d, v); err != nil {
		return Report{}, err
	}
	return r, nil
}

func setDiff(r *Report, d compare.Diff, v *policy.Verdict) error {
	if err := d.Validate(); err != nil {
		return err
	}
	dd, err := compare.DiffDigest(d)
	if err != nil {
		return err
	}
	if v != nil {
		if err := v.Validate(); err != nil {
			return err
		}
		if v.DiffDigest != dd {
			return fmt.Errorf("%w: the verdict judged diff %s, not %s", ErrInconsistent, v.DiffDigest, dd)
		}
	}
	r.Input.DiffDigest = dd
	r.Diff = &d
	r.Verdict = v
	return nil
}

// Marshal returns the report in canonical file form (two-space indentation,
// LF, one trailing newline).
func Marshal(r Report) ([]byte, error) {
	return trustfreeze.MarshalFile(r)
}

func captureSection(b *trustfreeze.Bundle) (*CaptureSection, error) {
	if b.Capture == nil {
		return nil, fmt.Errorf("%w: %s bundle without capture document", ErrUnsupportedInput, b.Manifest.Kind)
	}
	results, err := b.ReadProbeResults()
	if err != nil {
		return nil, err
	}
	arts := []trustfreeze.Artifact{}
	if b.State != nil {
		arts = append(arts, b.State.Artifacts...)
	}
	trustfreeze.SortArtifacts(arts)
	probes := slices.Clone(b.Capture.Probes)
	if probes == nil {
		probes = []trustfreeze.ProbeSummary{}
	}
	return &CaptureSection{
		Meta:         b.Capture.Capture,
		Completeness: b.Capture.Completeness,
		Probes:       probes,
		ProbeResults: results,
		Artifacts:    arts,
	}, nil
}

// readApproval reads approval.json through the core (manifest-checked bytes)
// and projects it as a generic JSON object. Integer numbers stay integers;
// any other number is refused, the canonical form has no floating point.
func readApproval(b *trustfreeze.Bundle) (map[string]any, error) {
	raw, err := b.ReadFile(trustfreeze.ApprovalFile)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("%w: approval.json: %w", ErrUnsupportedInput, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: approval.json: trailing data", ErrUnsupportedInput)
	}
	if obj == nil {
		return nil, fmt.Errorf("%w: approval.json is not an object", ErrUnsupportedInput)
	}
	schema, _ := obj["schema_version"].(string)
	if err := trustfreeze.CheckSchema(schema, trustfreeze.SchemaApproval); err != nil {
		return nil, fmt.Errorf("%w: approval.json: %w", ErrUnsupportedInput, err)
	}
	v, err := integersOnly(obj)
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

// integersOnly replaces every json.Number by its int64 value and refuses any
// number that is not an integer.
func integersOnly(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			n, err := integersOnly(e)
			if err != nil {
				return nil, err
			}
			t[k] = n
		}
		return t, nil
	case []any:
		for i, e := range t {
			n, err := integersOnly(e)
			if err != nil {
				return nil, err
			}
			t[i] = n
		}
		return t, nil
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return nil, fmt.Errorf("%w: approval.json: number %s is not an integer", ErrUnsupportedInput, t)
		}
		return i, nil
	}
	return v, nil
}
