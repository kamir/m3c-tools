// Package probe is the Trust Freeze probe execution seam (SPEC-0467): the
// Probe interface and its descriptor, the registry, the command runner (a
// real one that never uses a shell and a deterministic fake), the restricted
// file reader, per-probe limits and the support matrix.
//
// A probe only collects: it returns a trustfreeze.ProbeResult and never
// assigns a severity. Everything a command prints passes the redactor inside
// the runner before a probe sees it (SPEC-0467 R5).
package probe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Platform is an operating system family, spelled like runtime.GOOS.
type Platform string

// Platforms Trust Freeze knows.
const (
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformWindows Platform = "windows"
)

// AllPlatforms returns every platform, sorted.
func AllPlatforms() []Platform {
	return []Platform{PlatformDarwin, PlatformLinux, PlatformWindows}
}

// Valid reports whether p is a known platform.
func (p Platform) Valid() bool {
	switch p {
	case PlatformLinux, PlatformDarwin, PlatformWindows:
		return true
	}
	return false
}

// Privilege is the core privilege type; it is repeated here so probe authors
// need only this package for a descriptor.
type Privilege = trustfreeze.Privilege

// Privilege levels.
const (
	PrivilegeUser     = trustfreeze.PrivilegeUser
	PrivilegeElevated = trustfreeze.PrivilegeElevated
)

// ProbeDescriptor declares what a probe is (SPEC-0467 R1).
type ProbeDescriptor struct {
	// ID is a probe id such as "common.identity" (trustfreeze.ValidateProbeID).
	ID string
	// Version changes whenever the output of the probe can change.
	Version string
	// Platforms the probe is implemented for.
	Platforms []Platform
	// RequiredPrivilege is the privilege the probe needs for a full result.
	// Trust Freeze never elevates (SPEC-0467 R6); a probe that needs more than
	// it has reports permission_denied.
	RequiredPrivilege Privilege
	// DefaultTimeout bounds one run; zero means the engine limit.
	DefaultTimeout time.Duration
	// Sensitivity of the data the probe persists.
	Sensitivity trustfreeze.Sensitivity
	// Provides lists the artifact ids or id prefixes the probe emits.
	Provides []string
}

// ErrInvalidDescriptor is wrapped by ProbeDescriptor.Validate.
var ErrInvalidDescriptor = errors.New("probe: invalid descriptor")

// Validate checks the descriptor fields.
func (d ProbeDescriptor) Validate() error {
	if err := trustfreeze.ValidateProbeID(d.ID); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}
	if strings.TrimSpace(d.Version) == "" {
		return fmt.Errorf("%w: %s: empty version", ErrInvalidDescriptor, d.ID)
	}
	if len(d.Platforms) == 0 {
		return fmt.Errorf("%w: %s: no platform", ErrInvalidDescriptor, d.ID)
	}
	seen := map[Platform]bool{}
	for _, p := range d.Platforms {
		if !p.Valid() {
			return fmt.Errorf("%w: %s: unknown platform %q", ErrInvalidDescriptor, d.ID, p)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s: platform %q listed twice", ErrInvalidDescriptor, d.ID, p)
		}
		seen[p] = true
	}
	if !d.RequiredPrivilege.Valid() {
		return fmt.Errorf("%w: %s: required privilege %q", ErrInvalidDescriptor, d.ID, d.RequiredPrivilege)
	}
	if d.DefaultTimeout < 0 {
		return fmt.Errorf("%w: %s: negative default timeout", ErrInvalidDescriptor, d.ID)
	}
	if !d.Sensitivity.Valid() {
		return fmt.Errorf("%w: %s: sensitivity %q", ErrInvalidDescriptor, d.ID, d.Sensitivity)
	}
	for _, p := range d.Provides {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("%w: %s: empty provides entry", ErrInvalidDescriptor, d.ID)
		}
	}
	return nil
}

// SupportsPlatform reports whether goos is one of the declared platforms.
func (d ProbeDescriptor) SupportsPlatform(goos string) bool {
	for _, p := range d.Platforms {
		if string(p) == goos {
			return true
		}
	}
	return false
}

// Probe collects one area of host state (SPEC-0467).
type Probe interface {
	Descriptor() ProbeDescriptor
	// Support checks availability only; it must not collect or change
	// anything.
	Support(ctx context.Context, host HostContext) SupportResult
	// Collect runs the probe. The engine overrides ProbeID, ProbeVersion,
	// StartedAt, DurationMS, Privilege, Support, Tools and RawEvidence with
	// the values it observed itself, so a probe cannot misreport them.
	Collect(ctx context.Context, cc CollectContext) trustfreeze.ProbeResult
}

// SupportResult is the outcome of Probe.Support. When Available is false,
// Status says why and must be unsupported, unavailable, not_applicable or
// permission_denied; Reason gives the detail.
type SupportResult struct {
	Available bool
	Status    trustfreeze.ProbeStatus
	Reason    string
}

// Supported is the result of a probe that can run.
func Supported() SupportResult { return SupportResult{Available: true} }

// Unsupported: this build has no implementation for the host.
func Unsupported(reason string) SupportResult {
	return SupportResult{Status: trustfreeze.StatusUnsupported, Reason: reason}
}

// Unavailable: the feature should exist but the tool is missing.
func Unavailable(reason string) SupportResult {
	return SupportResult{Status: trustfreeze.StatusUnavailable, Reason: reason}
}

// NotApplicable: the OS has no such feature.
func NotApplicable(reason string) SupportResult {
	return SupportResult{Status: trustfreeze.StatusNotApplicable, Reason: reason}
}

// PermissionDenied: blocked by privilege.
func PermissionDenied(reason string) SupportResult {
	return SupportResult{Status: trustfreeze.StatusPermissionDenied, Reason: reason}
}

// ErrInvalidSupport is returned by SupportResult.Validate.
var ErrInvalidSupport = errors.New("probe: invalid support result")

// Validate checks that an unavailable result names an allowed status.
func (s SupportResult) Validate() error {
	if s.Available {
		if s.Status != "" && s.Status != trustfreeze.StatusCaptured {
			return fmt.Errorf("%w: available with status %q", ErrInvalidSupport, s.Status)
		}
		return nil
	}
	switch s.Status {
	case trustfreeze.StatusUnsupported, trustfreeze.StatusUnavailable,
		trustfreeze.StatusNotApplicable, trustfreeze.StatusPermissionDenied:
		return nil
	}
	return fmt.Errorf("%w: not available with status %q", ErrInvalidSupport, s.Status)
}

// Record converts the result into the persisted support record.
func (s SupportResult) Record() trustfreeze.SupportRecord {
	return trustfreeze.SupportRecord{Available: s.Available, Reason: s.Reason}
}

// HostContext is everything a probe may learn about the host. Every input is
// injectable so that each OS path runs on any host in tests (SPEC-0467 R9).
type HostContext struct {
	// GOOS and GOARCH of the collector (runtime.GOOS and runtime.GOARCH in
	// production). GOOS is the OS family of the observed host, since a build
	// runs only on its own OS. GOARCH is the build target, not a fact about
	// the machine (an amd64 build runs under Rosetta 2 or x64 emulation on
	// arm64): probes read the machine architecture from the OS instead.
	GOOS   string
	GOARCH string
	// Hostname returns the host name (os.Hostname in production).
	Hostname func() (string, error)
	// Files reads files, restricted to allowed roots.
	Files FileReader
	// Runner runs commands without a shell.
	Runner CommandRunner
	// Clock is the only time source.
	Clock trustfreeze.Clock
	// Privilege the process runs with. Recorded, never raised.
	Privilege Privilege
}

// ErrNoFileReader is returned by HostContext.ReadFile without a reader.
var ErrNoFileReader = errors.New("probe: no file reader configured")

// ReadFile reads name through the restricted reader.
func (h HostContext) ReadFile(name string) ([]byte, error) {
	if h.Files == nil {
		return nil, ErrNoFileReader
	}
	return h.Files.ReadFile(name)
}

// ErrInvalidHost is wrapped by HostContext.Validate.
var ErrInvalidHost = errors.New("probe: invalid host context")

// Validate checks that every field is set.
func (h HostContext) Validate() error {
	switch {
	case h.GOOS == "":
		return fmt.Errorf("%w: empty GOOS", ErrInvalidHost)
	case h.GOARCH == "":
		return fmt.Errorf("%w: empty GOARCH", ErrInvalidHost)
	case h.Hostname == nil:
		return fmt.Errorf("%w: no hostname function", ErrInvalidHost)
	case h.Files == nil:
		return fmt.Errorf("%w: no file reader", ErrInvalidHost)
	case h.Runner == nil:
		return fmt.Errorf("%w: no command runner", ErrInvalidHost)
	case h.Clock == nil:
		return fmt.Errorf("%w: no clock", ErrInvalidHost)
	case !h.Privilege.Valid():
		return fmt.Errorf("%w: privilege %q", ErrInvalidHost, h.Privilege)
	}
	return nil
}

// Subject returns the subject of the host and the hostname it was derived
// from (trustfreeze.SubjectID over GOOS and hostname). A host without a
// hostname has no stable subject, so that is an error.
func (h HostContext) Subject() (trustfreeze.Subject, string, error) {
	if h.Hostname == nil {
		return trustfreeze.Subject{}, "", fmt.Errorf("%w: no hostname function", ErrInvalidHost)
	}
	name, err := h.Hostname()
	if err != nil {
		return trustfreeze.Subject{}, "", fmt.Errorf("probe: hostname: %w", err)
	}
	if strings.TrimSpace(name) == "" {
		return trustfreeze.Subject{}, "", errors.New("probe: hostname is empty")
	}
	return trustfreeze.Subject{ID: trustfreeze.SubjectID(h.GOOS, name), OSFamily: h.GOOS}, name, nil
}

// NewHostContext returns the production host context: runtime GOOS and
// GOARCH, os.Hostname, a file reader restricted to roots, the exec runner
// with its fixed search path, the system clock and the detected privilege.
func NewHostContext(roots []string) HostContext {
	return HostContext{
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Hostname:  os.Hostname,
		Files:     NewRootedFileReader(roots, DefaultLimits().MaxFileBytes),
		Runner:    NewExecRunner(),
		Clock:     trustfreeze.SystemClock{},
		Privilege: DetectPrivilege(),
	}
}

// CollectContext is what Collect receives: the host plus the redactor, the
// limits and the evidence sink of this run.
type CollectContext struct {
	HostContext
	// ProbeID of the running probe.
	ProbeID string
	// Redactor for everything the probe reads outside the runner (files,
	// registry values). The runner redacts command output itself.
	Redactor *redact.Redactor
	// Limits of this run.
	Limits Limits
	// Evidence receives redacted raw evidence. May be nil: evidence is then
	// discarded.
	Evidence EvidenceSink
	// Support is the result of the Support call for this run.
	Support SupportResult
}

// Now returns the current time of the injected clock.
func (c CollectContext) Now() time.Time { return c.Clock.Now() }

// AddEvidence hands redacted raw evidence to the sink. Without a sink it
// returns the reference the sink would have produced and stores nothing.
func (c CollectContext) AddEvidence(name, source string, data redact.Redacted, truncated bool) (trustfreeze.EvidenceRef, error) {
	if c.Evidence == nil {
		return evidenceRef(c.ProbeID, name, source, data, truncated)
	}
	return c.Evidence.Add(name, source, data, truncated)
}

// EvidenceSink receives the redacted raw evidence of one probe run. It only
// accepts redact.Redacted, so unredacted bytes cannot reach it.
type EvidenceSink interface {
	Add(name, source string, data redact.Redacted, truncated bool) (trustfreeze.EvidenceRef, error)
}

// Evidence errors.
var (
	ErrEvidenceClosed    = errors.New("probe: evidence sink is closed")
	ErrEvidenceDuplicate = errors.New("probe: evidence name already used")
)

// EvidenceItem is one buffered evidence file.
type EvidenceItem struct {
	Name      string
	Source    string
	Data      redact.Redacted
	Truncated bool
	Ref       trustfreeze.EvidenceRef
}

// EvidenceBuffer is the EvidenceSink the capture engine uses: it keeps the
// evidence in memory, enforces the file count and size limits, and hands the
// items over once the probe has finished (Close). Adds after Close fail, so a
// probe that outlives its timeout cannot add evidence later.
type EvidenceBuffer struct {
	mu      sync.Mutex
	probeID string
	limits  Limits
	items   []EvidenceItem
	names   map[string]bool
	closed  bool
	// refused counts every Add that stored nothing, whatever the probe did
	// with the error; the engine caps such a run at partial.
	refused int
}

// NewEvidenceBuffer returns an empty buffer for probeID.
func NewEvidenceBuffer(probeID string, limits Limits) *EvidenceBuffer {
	return &EvidenceBuffer{probeID: probeID, limits: limits.WithDefaults(), names: map[string]bool{}}
}

// Add stores one evidence file under evidence/<probe-id>/<name>. Every
// refusal (bad name, duplicate, limit) is counted, see Refused.
func (b *EvidenceBuffer) Add(name, source string, data redact.Redacted, truncated bool) (ref trustfreeze.EvidenceRef, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer func() {
		if err != nil && !b.closed {
			b.refused++
		}
	}()
	ref, err = evidenceRef(b.probeID, name, source, data, truncated)
	if err != nil {
		return trustfreeze.EvidenceRef{}, err
	}
	if b.closed {
		return trustfreeze.EvidenceRef{}, ErrEvidenceClosed
	}
	key := trustfreeze.PathFoldKey(name)
	if b.names[key] {
		return trustfreeze.EvidenceRef{}, fmt.Errorf("%w: %s", ErrEvidenceDuplicate, name)
	}
	if len(b.items) >= b.limits.MaxFiles {
		return trustfreeze.EvidenceRef{}, fmt.Errorf("%w: more than %d evidence files", ErrLimitExceeded, b.limits.MaxFiles)
	}
	if ref.Size > b.limits.MaxFileBytes {
		return trustfreeze.EvidenceRef{}, fmt.Errorf("%w: evidence %s has %d bytes, limit %d", ErrLimitExceeded, name, ref.Size, b.limits.MaxFileBytes)
	}
	b.names[key] = true
	b.items = append(b.items, EvidenceItem{Name: name, Source: source, Data: data, Truncated: truncated, Ref: ref})
	return ref, nil
}

// Refused returns how many Add calls stored nothing before Close, whether
// or not the probe reported the error (SPEC-0467 section 5.3: an evidence
// limit caps the probe at partial).
func (b *EvidenceBuffer) Refused() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.refused
}

// Close stops further adds and returns the items sorted by name.
func (b *EvidenceBuffer) Close() []EvidenceItem {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	out := append([]EvidenceItem(nil), b.items...)
	sort.Slice(out, func(i, j int) bool { return out[i].Ref.Path < out[j].Ref.Path })
	return out
}

func evidenceRef(probeID, name, source string, data redact.Redacted, truncated bool) (trustfreeze.EvidenceRef, error) {
	p, err := trustfreeze.EvidencePath(probeID, name)
	if err != nil {
		return trustfreeze.EvidenceRef{}, err
	}
	b := data.Bytes()
	return trustfreeze.EvidenceRef{
		Path:      p,
		Size:      int64(len(b)),
		SHA256:    trustfreeze.SHA256Hex(b),
		Source:    source,
		Truncated: truncated,
	}, nil
}

// Diagnostic codes used by probes and the engine, in addition to the core
// codes (trustfreeze.DiagFieldMissing, DiagOutputTruncated,
// DiagRedactionFailed).
const (
	// DiagFieldUnavailable: the tool that provides the field is missing.
	DiagFieldUnavailable = "field_unavailable"
	// DiagFieldPermissionDenied: reading the field was blocked by privilege.
	DiagFieldPermissionDenied = "field_permission_denied"
	// DiagFieldTimeout: the source of the field timed out.
	DiagFieldTimeout = "field_timeout"
	// DiagFieldFailed: the source of the field failed otherwise.
	DiagFieldFailed = "field_failed"
	// DiagFieldNotApplicable: the OS has no such field.
	DiagFieldNotApplicable = "field_not_applicable"
	// DiagValueRedacted: the engine redacted values in the probe result.
	DiagValueRedacted = "value_redacted"
	// DiagArtifactDropped: the engine dropped an invalid or duplicate artifact.
	DiagArtifactDropped = "artifact_dropped"
	// DiagEvidenceDropped: evidence was refused (limit, name) and not persisted.
	DiagEvidenceDropped = "evidence_dropped"
)
