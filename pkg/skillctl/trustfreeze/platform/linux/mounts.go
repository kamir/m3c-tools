package linux

// linux.mounts (SPEC-0471 TF06-R3) reports the mount table of the host, one
// artifact per mount point.
//
// Source: "findmnt --json" with an explicit column list. The column list is
// explicit so that the parsed keys never depend on a util-linux default that
// a newer version may change; the four columns asked for are the ones
// findmnt prints by default, which is why the fixture (taken with the bare
// "findmnt --json") carries exactly these keys.
//
// findmnt reads the kernel mount table and does not walk into the mounted
// filesystems, so this probe never stats a mount point itself. That matters
// on a bastion with a hung network mount: a stat would block in
// uninterruptible sleep past the probe deadline (the note on ExecRunner in
// probe/runner.go).
//
// What is persisted, and what is not: a mount carries its target, its source
// and its filesystem type, plus the options that decide what may be done on
// it (ro, nosuid, nodev, noexec) and whether the mount root is a subtree of
// the source filesystem, which is the shape a bind mount into a container
// path has. Everything else in the option string stays out: size=,
// nr_inodes=, fd=, pgrp=, pipe_ino= and the lowerdir chain of an overlay are
// either volatile or long, and a bundle has to be comparable byte for byte
// between two captures of an unchanged host (playbook L6, L8).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// Probe and artifact identity.
const (
	// MountsProbeID is the probe id.
	MountsProbeID = "linux.mounts"
	// MountsProbeVersion changes whenever the output of the probe can change.
	MountsProbeVersion = "1"

	// ArtifactMountTable summarizes the table that was read.
	ArtifactMountTable = "system/mounts"
	// ArtifactMountPrefix prefixes one mount point; the target follows, with
	// the characters an artifact id may not carry replaced
	// (mountArtifactSuffix). The raw target stays in the mount_target
	// attribute.
	ArtifactMountPrefix = "system/mount/"
)

// findmntExe is the only executable this probe runs.
const findmntExe = "findmnt"

// findmntColumns is the explicit column list. TARGET, SOURCE, FSTYPE and
// OPTIONS map to the JSON keys target, source, fstype and options.
const findmntColumns = "TARGET,SOURCE,FSTYPE,OPTIONS"

// mountsMaxRecords caps the number of mount points one capture records, so an
// unexpected host cannot turn one probe into tens of thousands of artifacts.
// A cut table is reported, never silent.
const mountsMaxRecords = 4096

// mountsMaxIssueDiagnostics caps the per-record diagnostics; the rest is
// summarized in one diagnostic.
const mountsMaxIssueDiagnostics = 20

// mountsMaxValueBytes caps a single recorded value, so an unexpected tool
// answer cannot inflate an artifact (playbook L6).
const mountsMaxValueBytes = 200

// Attribute names of the mount artifacts.
const (
	mountsAttrTarget    = "mount_target"
	mountsAttrSource    = "source"
	mountsAttrMountRoot = "mount_root"
	mountsAttrFSType    = "fstype"
	mountsAttrReadOnly  = "read_only"
	mountsAttrNoSUID    = "nosuid"
	mountsAttrNoDev     = "nodev"
	mountsAttrNoExec    = "noexec"
	mountsAttrSubtree   = "subtree_mount"
	mountsAttrCount     = "mount_count"
)

// Values of the option attributes. A flag is yes or no because the kernel
// mount table lists every flag that is set, so an absent flag is a fact.
// read_only is the exception: ro and rw are two spellings of one flag, and a
// table that carries neither leaves the question open.
const (
	MountValueYes     = "yes"
	MountValueNo      = "no"
	MountValueUnknown = "unknown"
)

// Diagnostic codes this probe adds to the shared ones.
const (
	// DiagMountsExitCode: findmnt ended with a non-zero exit code.
	DiagMountsExitCode = "tool_exit_code"
	// DiagMountsUnreadRecord: one record of the table could not be used.
	DiagMountsUnreadRecord = "record_not_read"
	// DiagMountsToolVersionUnknown: the tool version could not be read. An
	// unknown version is a diagnostic, never a guess (playbook L7).
	DiagMountsToolVersionUnknown = "tool_version_unknown"
	// DiagMountsTableTruncated: the table hit mountsMaxRecords.
	DiagMountsTableTruncated = "table_truncated"
)

// MountsProbe implements probe.Probe for linux.mounts.
type MountsProbe struct{}

// NewMountsProbe returns the probe.
func NewMountsProbe() *MountsProbe { return &MountsProbe{} }

// Descriptor implements probe.Probe.
func (p *MountsProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                MountsProbeID,
		Version:           MountsProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    30 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactMountPrefix, ArtifactMountTable},
	}
}

// EvidenceClaims implements probe.EvidenceClaimer: the parser is covered by
// fixture tests that run on any host, and the package compiles for linux.
// Whether the probe ran on a real Linux host is not decided in code
// (SPEC-0471 TF06-R7).
func (p *MountsProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// RequiredTools names the executables this probe runs, for the doctor check
// that resolves them before a capture (capture.ToolUser).
func (p *MountsProbe) RequiredTools() []string { return []string{findmntExe} }

// Support implements probe.Probe. It only checks availability: it resolves
// findmnt through LookPath and never starts it. A missing findmnt is a
// missing tool and therefore unavailable (playbook L1), not not_applicable:
// the mount table exists on every Linux host, only the reader is absent.
func (p *MountsProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("linux.mounts has no source on " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if _, err := host.Runner.LookPath(findmntExe); err != nil {
		switch {
		case errors.Is(err, probe.ErrPermissionDenied):
			return probe.PermissionDenied("findmnt is not executable: " + err.Error())
		case errors.Is(err, probe.ErrToolMissing):
			return probe.Unavailable("findmnt not found in the runner search path")
		}
		return probe.Unavailable("findmnt: " + err.Error())
	}
	return probe.Supported()
}

// Collect implements probe.Probe.
func (p *MountsProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	c := &mountsCollector{ctx: ctx, cc: cc, start: cc.Now(), status: trustfreeze.StatusCaptured}
	c.collectVersion()
	entries, ok := c.collectTable()
	if !ok {
		return c.result()
	}
	c.buildArtifacts(entries)
	return c.result()
}

// mountsCollector gathers one Collect call.
type mountsCollector struct {
	ctx   context.Context
	cc    probe.CollectContext
	start time.Time

	status   trustfreeze.ProbeStatus
	errClass string
	reasons  []string

	toolVersion string
	sources     []string
	tools       []trustfreeze.ToolInvocation
	warnings    []trustfreeze.Diagnostic
	artifacts   []trustfreeze.Artifact
}

func (c *mountsCollector) warn(code, field, msg string) {
	c.warnings = append(c.warnings, trustfreeze.Diagnostic{Code: code, Field: field, Message: msg})
}

// degrade lowers a captured run to partial. A terminal status set by fail
// stays untouched.
func (c *mountsCollector) degrade(reason string) {
	if c.status == trustfreeze.StatusCaptured {
		c.status = trustfreeze.StatusPartial
	}
	c.reasons = append(c.reasons, reason)
}

// fail sets the terminal status of a run whose primary source did not answer.
func (c *mountsCollector) fail(status trustfreeze.ProbeStatus, class, reason string) {
	c.status, c.errClass = status, class
	c.reasons = append(c.reasons, reason)
}

// exec runs one findmnt call through the injected runner.
func (c *mountsCollector) exec(args []string) probe.CommandResult {
	res := c.cc.Runner.Run(c.ctx, probe.CommandRequest{
		Executable: findmntExe,
		Args:       args,
		Redactor:   c.cc.Redactor,
	})
	c.tools = append(c.tools, res.Invocation())
	return res
}

// evidence stores one redacted stream of a call.
func (c *mountsCollector) evidence(name, source string, res probe.CommandResult, stderr bool) {
	data, truncated := res.Stdout, res.StdoutTruncated
	if stderr {
		data, truncated = res.Stderr, res.StderrTruncated
	}
	if len(data.Bytes()) == 0 {
		return
	}
	if _, err := c.cc.AddEvidence(name, source, data, truncated); err != nil {
		c.warn(probe.DiagEvidenceDropped, "", name+": "+err.Error())
	}
}

// collectVersion records the findmnt version (playbook L7).
func (c *mountsCollector) collectVersion() {
	res := c.exec([]string{"--version"})
	switch {
	case res.Err != nil:
		c.warn(DiagMountsToolVersionUnknown, "", "findmnt --version: "+res.Err.Error())
		return
	case res.RedactionFailed:
		c.warn(DiagMountsToolVersionUnknown, "", "findmnt --version output could not be redacted and was dropped")
		return
	case res.ExitCode != 0:
		c.warn(DiagMountsToolVersionUnknown, "", fmt.Sprintf("findmnt --version exited %d", res.ExitCode))
		return
	}
	v, err := ParseFindmntVersion(res.Stdout.Bytes())
	if err != nil {
		c.warn(DiagMountsToolVersionUnknown, "", "findmnt --version: "+err.Error())
		return
	}
	c.evidence("findmnt-version.txt", "stdout:findmnt", res, false)
	c.toolVersion = v
}

// collectTable reads the mount table. The bool reports whether the run may
// continue.
func (c *mountsCollector) collectTable() ([]MountEntry, bool) {
	res := c.exec([]string{"--json", "-o", findmntColumns})
	if res.Err != nil {
		status, class := mountsFailureFor(res.Err)
		c.fail(status, class, "findmnt --json: "+res.Err.Error())
		return nil, false
	}
	if res.RedactionFailed {
		c.warn(trustfreeze.DiagRedactionFailed, "", "findmnt output dropped (fail-closed)")
		c.fail(trustfreeze.StatusFailed, probe.ClassRedactionFailed, "findmnt output could not be redacted")
		return nil, false
	}
	c.evidence("findmnt.json", "stdout:findmnt", res, false)
	c.evidence("findmnt.stderr.txt", "stderr:findmnt", res, true)
	out := res.Stdout.Bytes()
	if res.StdoutTruncated {
		// A truncated JSON document is not a short table, it is an unreadable
		// one: say so instead of parsing a fragment.
		stdoutCap, _ := outputCap(c.cc)
		c.warn(trustfreeze.DiagOutputTruncated, "mount_table",
			truncationNote("findmnt", "stdout", len(out), res.StdoutBytes, stdoutCap,
				"a cut JSON document is unreadable, so no mount point was recorded"))
		c.fail(trustfreeze.StatusFailed, probe.ClassLimitExceeded, "findmnt output exceeded the output limit")
		return nil, false
	}
	if res.ExitCode != 0 {
		switch {
		case len(out) > 0:
			c.warn(DiagMountsExitCode, "mount_table", fmt.Sprintf("findmnt exited %d after writing output; the table may be incomplete", res.ExitCode))
			c.degrade("findmnt exited " + strconv.Itoa(res.ExitCode))
		case len(res.Stderr.Bytes()) > 0:
			// Output on stderr and nothing on stdout: no table was produced.
			// The refusal text stays in the evidence and is not retold here
			// (playbook L4).
			c.fail(trustfreeze.StatusFailed, probe.ClassTerminated,
				fmt.Sprintf("findmnt exited %d with no output and %d bytes on stderr", res.ExitCode, len(res.Stderr.Bytes())))
			return nil, false
		default:
			c.warn(DiagMountsExitCode, "mount_table", fmt.Sprintf("findmnt exited %d with no output: no mount point is listed", res.ExitCode))
			return nil, true
		}
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		// An empty result that is genuinely empty is captured with an empty
		// list, and the artifact says so (playbook L1).
		c.warn(trustfreeze.DiagFieldMissing, "mount_table", "findmnt printed no document: no mount point is listed")
		return nil, true
	}
	entries, issues, err := ParseFindmntJSON(out)
	if err != nil {
		c.warn(DiagMountsUnreadRecord, "mount_table", "findmnt document: "+err.Error())
		c.fail(trustfreeze.StatusFailed, MountsClassParseFailed, "the findmnt document could not be read")
		return nil, false
	}
	if len(issues) > 0 {
		shown := issues
		if len(shown) > mountsMaxIssueDiagnostics {
			shown = shown[:mountsMaxIssueDiagnostics]
		}
		for _, is := range shown {
			c.warn(DiagMountsUnreadRecord, "mount_table", fmt.Sprintf("findmnt record %s: %s", is.Path, is.Reason))
		}
		if rest := len(issues) - len(shown); rest > 0 {
			c.warn(DiagMountsUnreadRecord, "mount_table", fmt.Sprintf("findmnt document: %d further records were not read", rest))
		}
		c.degrade(fmt.Sprintf("%d record(s) of the mount table were not read", len(issues)))
	}
	if len(entries) > mountsMaxRecords {
		c.warn(DiagMountsTableTruncated, "mount_table", fmt.Sprintf("more than %d mount points; the rest was not recorded", mountsMaxRecords))
		c.degrade("mount table truncated")
		entries = entries[:mountsMaxRecords]
	}
	c.sources = append(c.sources, "command:findmnt --json")
	return entries, true
}

// buildArtifacts turns the mount table into artifacts.
//
// Sorting is by target, then filesystem type, then source, then the option
// string, so two captures of an unchanged host produce the same order
// whatever order the kernel listed the mounts in (playbook L8). The sort also
// fixes the id of an overmount: a mount point can carry more than one mount
// (the trial host has an autofs and a binfmt_misc mount at
// /proc/sys/fs/binfmt_misc), and the second and further mounts at one target
// get a numbered id suffix in that deterministic order.
func (c *mountsCollector) buildArtifacts(entries []MountEntry) {
	sorted := append([]MountEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		switch {
		case a.Target != b.Target:
			return a.Target < b.Target
		case a.FSType != b.FSType:
			return a.FSType < b.FSType
		case a.Source != b.Source:
			return a.Source < b.Source
		}
		return strings.Join(a.Options, ",") < strings.Join(b.Options, ",")
	})

	prov := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     append([]string(nil), c.sources...),
		ObservedAt:  trustfreeze.FormatTime(c.start),
		ToolVersion: c.toolVersion,
	}
	sort.Strings(prov.Sources)

	used := map[string]int{}
	kept := 0
	for _, e := range sorted {
		base := ArtifactMountPrefix + mountArtifactSuffix(e.Target)
		id := base
		if n := used[base]; n > 0 {
			id = base + "+" + strconv.Itoa(n+1)
		}
		used[base]++
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			c.warn(probe.DiagArtifactDropped, mountsAttrTarget, "mount target yields no valid artifact id")
			c.degrade("a mount artifact was dropped")
			continue
		}
		c.artifacts = append(c.artifacts, trustfreeze.Artifact{
			ID: id, Type: "mount", Scope: "system", Source: MountsProbeID,
			// The kernel mount table is what is mounted right now.
			State:       trustfreeze.StateObserved,
			Attributes:  mountAttributes(e),
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
		kept++
	}

	c.artifacts = append(c.artifacts, trustfreeze.Artifact{
		ID: ArtifactMountTable, Type: "mount-table", Scope: "system", Source: MountsProbeID,
		State:       trustfreeze.StateObserved,
		Attributes:  map[string]string{mountsAttrCount: strconv.Itoa(kept)},
		Provenance:  prov,
		Sensitivity: trustfreeze.SensitivityInternal,
	})
}

// mountAttributes builds the attribute set of one mount point.
func mountAttributes(e MountEntry) map[string]string {
	name, root := SplitMountSource(e.Source)
	flags := MountTrustOptions(e.Options)
	attrs := map[string]string{
		// The raw target, unchanged: a bind mount into a container path is
		// only interesting if the path is readable as it is.
		mountsAttrTarget:   e.Target,
		mountsAttrFSType:   e.FSType,
		mountsAttrReadOnly: flags.ReadOnly,
		mountsAttrNoSUID:   flags.NoSUID,
		mountsAttrNoDev:    flags.NoDev,
		mountsAttrNoExec:   flags.NoExec,
		mountsAttrSubtree:  MountValueNo,
	}
	if name != "" {
		attrs[mountsAttrSource] = name
	}
	// A mount root that is a path is a subtree of the source filesystem: a
	// bind mount, or a subvolume of it. A mount root that is not a path is a
	// runtime identifier of a pseudo filesystem (nsfs prints the namespace
	// inode as "net:[4026531833]"), which changes on every reboot and is
	// therefore not recorded (playbook L8).
	if strings.HasPrefix(root, "/") {
		attrs[mountsAttrMountRoot] = root
		attrs[mountsAttrSubtree] = MountValueYes
	}
	return attrs
}

// result builds the persisted result.
func (c *mountsCollector) result() trustfreeze.ProbeResult {
	for i := range c.artifacts {
		if d, err := trustfreeze.ComputeArtifactDigest(c.artifacts[i]); err == nil {
			c.artifacts[i].Digest = d
		}
	}
	trustfreeze.SortArtifacts(c.artifacts)
	res := trustfreeze.ProbeResult{
		ProbeID:         MountsProbeID,
		ProbeVersion:    MountsProbeVersion,
		Status:          c.status,
		Reason:          strings.Join(c.reasons, "; "),
		Support:         c.cc.Support.Record(),
		StartedAt:       trustfreeze.FormatTime(c.start),
		DurationMS:      c.cc.Now().Sub(c.start).Milliseconds(),
		Privilege:       c.cc.Privilege,
		Tools:           c.tools,
		NormalizedState: c.artifacts,
		Warnings:        c.warnings,
	}
	if c.errClass != "" {
		res.Error = &trustfreeze.ProbeError{Class: c.errClass, Message: res.Reason}
	}
	return res
}

// MountsClassParseFailed is the probe error class of a findmnt document that
// could not be decoded.
const MountsClassParseFailed = "parse_failed"

// mountsFailureFor maps a runner error to the honest probe status
// (playbook L1).
func mountsFailureFor(err error) (trustfreeze.ProbeStatus, string) {
	switch {
	case errors.Is(err, probe.ErrToolMissing):
		return trustfreeze.StatusUnavailable, probe.ClassToolMissing
	case errors.Is(err, probe.ErrPermissionDenied):
		return trustfreeze.StatusPermissionDenied, probe.ClassPermissionDenied
	case errors.Is(err, probe.ErrTimeout):
		return trustfreeze.StatusTimeout, probe.ClassTimeout
	}
	return trustfreeze.StatusFailed, probe.ErrorClass(err)
}

// mountArtifactSuffix builds the artifact id suffix of one mount target. An
// artifact id is never an absolute path (SPEC-0466 R4), so the leading slash
// goes; the root mount becomes "root"; and every character an id may not
// carry is replaced. The raw target stays in the mount_target attribute.
func mountArtifactSuffix(target string) string {
	t := strings.TrimPrefix(target, "/")
	if t == "" {
		return "root"
	}
	segs := strings.Split(t, "/")
	for i, seg := range segs {
		switch seg {
		case "":
			segs[i] = "_"
			continue
		case ".":
			segs[i] = "_"
			continue
		case "..":
			segs[i] = "__"
			continue
		}
		var b strings.Builder
		b.Grow(len(seg))
		for _, r := range seg {
			switch {
			case r <= 0x20, r == 0x7f, r == '\\', r == '~', r == ':':
				b.WriteByte('_')
			default:
				b.WriteRune(r)
			}
		}
		segs[i] = b.String()
	}
	return strings.Join(segs, "/")
}

// ---------------------------------------------------------------------------
// Pure parsers. Everything below works on bytes only, so every shape is table
// tested from the fixtures on any operating system.
// ---------------------------------------------------------------------------

// MountEntry is one mount point of the findmnt table, flattened out of the
// tree findmnt prints. Every value is exactly what the tool reported.
type MountEntry struct {
	// Target is the mount point, for example "/run/user/1000".
	Target string
	// Source is the SOURCE column as findmnt printed it, including the mount
	// root in brackets when there is one ("tmpfs[/snapd/ns]").
	Source string
	// FSType is the filesystem type, for example "overlay".
	FSType string
	// Options are the mount options in the order findmnt printed them.
	Options []string
	// Depth is the nesting depth in the findmnt tree, 0 for a top level
	// entry. It is not persisted: it changes with the mount order and says
	// nothing the target does not already say.
	Depth int
}

// MountIssue is one findmnt record ParseFindmntJSON could not use. Path is
// the position in the document, never a value from it.
type MountIssue struct {
	Path   string
	Reason string
}

// Reasons of a MountIssue.
const (
	MountIssueNoTarget = "record has no target"
	MountIssueTooDeep  = "record nested deeper than the parser follows"
)

// mountsMaxDepth bounds the recursion over the findmnt tree. The deepest
// nesting a mount table can produce is bounded by the path depth, so a
// document that goes deeper is malformed and is reported, not followed.
const mountsMaxDepth = 64

// findmntDoc is the document findmnt --json prints. Pointer fields tell an
// absent key apart from an empty value: findmnt prints null for a source it
// does not know.
type findmntDoc struct {
	Filesystems []findmntNode `json:"filesystems"`
}

type findmntNode struct {
	Target   *string       `json:"target"`
	Source   *string       `json:"source"`
	FSType   *string       `json:"fstype"`
	Options  *string       `json:"options"`
	Children []findmntNode `json:"children"`
}

// ParseFindmntJSON flattens the findmnt document into one entry per mount
// point, in document order (which is the kernel's mount order; the probe
// sorts them itself).
//
// findmnt prints a tree: a mount that sits below another mount is a child of
// it, and the same target can appear twice, once for each mount stacked on
// it. Both are kept, because an overmount hides what is below it and that is
// a fact about the host.
//
// A record without a target is not a mount point and is returned as an issue.
// A document that is not the expected object returns an error: half a mount
// table is worse than an honest failure.
func ParseFindmntJSON(b []byte) ([]MountEntry, []MountIssue, error) {
	var doc findmntDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("linux.mounts: findmnt json: %w", err)
	}
	var (
		out    []MountEntry
		issues []MountIssue
	)
	var walk func(nodes []findmntNode, depth int, path string)
	walk = func(nodes []findmntNode, depth int, path string) {
		for i, n := range nodes {
			here := fmt.Sprintf("%s[%d]", path, i)
			if depth >= mountsMaxDepth {
				issues = append(issues, MountIssue{Path: here, Reason: MountIssueTooDeep})
				continue
			}
			target := ""
			if n.Target != nil {
				target = strings.TrimSpace(*n.Target)
			}
			if target == "" {
				issues = append(issues, MountIssue{Path: here, Reason: MountIssueNoTarget})
			} else {
				e := MountEntry{Target: target, Depth: depth}
				if n.Source != nil {
					e.Source = *n.Source
				}
				if n.FSType != nil {
					e.FSType = *n.FSType
				}
				if n.Options != nil {
					e.Options = SplitMountOptions(*n.Options)
				}
				out = append(out, e)
			}
			if len(n.Children) > 0 {
				walk(n.Children, depth+1, here+".children")
			}
		}
	}
	walk(doc.Filesystems, 0, "filesystems")
	return out, issues, nil
}

// SplitMountOptions splits an option string into its comma separated options.
// An empty string yields no option.
func SplitMountOptions(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SplitMountSource splits a findmnt SOURCE value into the device or
// filesystem name and the mount root findmnt prints in brackets after it.
//
//	/dev/sdb1               name "/dev/sdb1",  root ""
//	tmpfs[/snapd/ns]        name "tmpfs",      root "/snapd/ns"
//	nsfs[net:[4026531833]]  name "nsfs",       root "net:[4026531833]"
//
// The split is at the FIRST bracket and the value has to end at the last one,
// so a nested bracket stays inside the root.
func SplitMountSource(source string) (name, root string) {
	s := strings.TrimSpace(source)
	i := strings.IndexByte(s, '[')
	if i <= 0 || !strings.HasSuffix(s, "]") {
		return s, ""
	}
	return s[:i], s[i+1 : len(s)-1]
}

// MountFlags are the mount options that decide what may be done on a mount.
type MountFlags struct {
	// ReadOnly is MountValueYes for ro, MountValueNo for rw and
	// MountValueUnknown when the table carries neither.
	ReadOnly string
	// NoSUID, NoDev and NoExec are MountValueYes when the flag is set. The
	// kernel mount table lists every flag that is set, so an absent flag is
	// MountValueNo and not unknown.
	NoSUID string
	NoDev  string
	NoExec string
}

// MountTrustOptions reads the trust relevant flags out of the option list.
// Every other option is ignored here on purpose: the size, inode, uid, gid,
// pipe inode and lowerdir values of a mount are either volatile or long, and
// neither belongs in an artifact (playbook L6, L8).
func MountTrustOptions(options []string) MountFlags {
	f := MountFlags{
		ReadOnly: MountValueUnknown,
		NoSUID:   MountValueNo,
		NoDev:    MountValueNo,
		NoExec:   MountValueNo,
	}
	for _, o := range options {
		// An option with a value ("size=2452148k") is not a flag.
		if strings.Contains(o, "=") {
			continue
		}
		switch o {
		case "ro":
			f.ReadOnly = MountValueYes
		case "rw":
			f.ReadOnly = MountValueNo
		case "nosuid":
			f.NoSUID = MountValueYes
		case "nodev":
			f.NoDev = MountValueYes
		case "noexec":
			f.NoExec = MountValueYes
		}
	}
	return f
}

// ParseFindmntVersion returns the first line of "findmnt --version", for
// example "findmnt from util-linux 2.39.3". A parser is only valid for the
// versions it was measured against (playbook L7).
func ParseFindmntVersion(b []byte) (string, error) {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		if len(line) > mountsMaxValueBytes {
			line = strings.ToValidUTF8(line[:mountsMaxValueBytes], "")
		}
		return line, nil
	}
	return "", errors.New("linux.mounts: findmnt --version printed no line")
}
