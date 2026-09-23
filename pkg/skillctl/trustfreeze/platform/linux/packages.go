// Trust Freeze probe linux.packages (SPEC-0471 TF06-R3): the software
// inventory of a Debian or Ubuntu host.
//
// Sources, in this order: dpkg-query with an explicit format string for the
// package database, apt-mark showmanual for the install reason, and snap list
// where snapd exists. Every parser is a pure function over the bytes a tool
// printed, so the fixtures under testdata/packages exercise all of them on any
// operating system.
//
// This file also carries the helpers that the two inventory probes of this
// package share (linux.packages and linux.users). They are named with the inv
// prefix.

package linux

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// linux.packages identity.
const (
	PackagesProbeID      = "linux.packages"
	PackagesProbeVersion = "1"
)

// Artifact id prefixes of linux.packages. A dpkg package keeps the name dpkg
// itself prints, which is multiarch qualified where dpkg qualifies it
// ("zlib1g:amd64"), so the id is unique without an architecture segment. Snaps
// live in a namespace of their own because a snap and a dpkg package may carry
// the same name and are two different objects.
const (
	ArtifactPackagePrefix = "os/package/"
	ArtifactSnapPrefix    = "os/snap/"
)

// Executables linux.packages runs.
const (
	dpkgQueryTool = "dpkg-query"
	aptMarkTool   = "apt-mark"
	snapTool      = "snap"
)

// DpkgQueryFormat is the -f argument of the inventory call. The two-character
// sequences reach dpkg-query as a backslash followed by t or n, and dpkg-query
// itself turns them into a tab and a newline; the Go string must therefore not
// contain a real tab. An explicit format is what makes the output parseable
// (playbook L6): field order and field count are ours, not the tool's default.
const DpkgQueryFormat = `-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n`

// Volume guards. A bastion carries a few thousand packages and a few hundred
// accounts; these caps keep one probe result bounded even on a much larger
// host. Reaching a cap is never silent: the list is sorted first, the excess
// is dropped and the probe reports partial with a diagnostic that names the
// counts (playbook L1, L6).
const (
	maxPackageArtifacts = 5000
	maxUserArtifacts    = 2000
	maxGroupArtifacts   = 2000
)

// invMaxIssueDiagnostics bounds the "one diagnostic per unparsed record" rule
// of playbook L1: beyond it, one further diagnostic states how many records
// were not listed.
const invMaxIssueDiagnostics = 50

// invMaxNamesInAttribute bounds a name list persisted in an artifact
// attribute, invMaxNamesInMessage a name list inside a diagnostic message.
const (
	invMaxNamesInAttribute = 64
	invMaxNamesInMessage   = 16
)

// Diagnostic codes of the inventory probes. They are unexported so that the
// other probe families of this package can pick their own names freely.
const (
	// invDiagRecordUnparsed: one record of a tool output had a shape the
	// parser does not accept.
	invDiagRecordUnparsed = "record_unparsed"
	// invDiagToolVersionUnknown: the version of a tool that was used could
	// not be read (playbook L7: an unknown version is a diagnostic, never a
	// silent guess).
	invDiagToolVersionUnknown = "tool_version_unknown"
	// invDiagLimitExceeded: a volume cap dropped objects.
	invDiagLimitExceeded = "limit_exceeded"
	// invDiagEmptyResult: a tool answered with no records at all.
	invDiagEmptyResult = "empty_result"
	// invDiagValueTruncatedByTool: the tool itself shortened a value before
	// printing it, so the recorded value is the display form.
	invDiagValueTruncatedByTool = "value_truncated_by_tool"
)

// PackagesProbe is linux.packages.
type PackagesProbe struct{}

// NewPackagesProbe returns the probe.
func NewPackagesProbe() *PackagesProbe { return &PackagesProbe{} }

// Descriptor implements probe.Probe.
func (p *PackagesProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                PackagesProbeID,
		Version:           PackagesProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    60 * time.Second,
		Sensitivity:       trustfreeze.SensitivityPublic,
		Provides:          []string{ArtifactPackagePrefix, ArtifactSnapPrefix},
	}
}

// RequiredTools implements the structural ToolUser interface of the capture
// package: doctor resolves these names through LookPath and never runs one.
func (p *PackagesProbe) RequiredTools() []string {
	return []string{aptMarkTool, dpkgQueryTool, snapTool}
}

// EvidenceClaims implements probe.EvidenceClaimer. Every parser is covered by
// fixture tests that run on any host, and the package compiles for linux. A
// real platform run is evidence outside the code (SPEC-0471 TF06-R7).
func (p *PackagesProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe. It checks availability only: the platform
// and whether the package database can be asked at all. A host without
// dpkg-query is not a host without packages, so the honest answer is
// unavailable with a reason, never an empty inventory (playbook L1).
func (p *PackagesProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("linux.packages has no source on " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if _, err := host.Runner.LookPath(dpkgQueryTool); err != nil {
		if probe.ErrorClass(err) == probe.ClassPermissionDenied {
			return probe.PermissionDenied(dpkgQueryTool + " is present but not executable for this account")
		}
		return probe.Unavailable(dpkgQueryTool + " was not found: this build reads the package inventory of a dpkg based distribution only")
	}
	return probe.Supported()
}

// Collect implements probe.Probe.
func (p *PackagesProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := invNewCollector(ctx, cc)
	res := invBaseResult(PackagesProbeID, PackagesProbeVersion, cc, start)
	if cc.Runner == nil {
		return c.fail(res, trustfreeze.StatusFailed, probe.ClassInvalidRequest, "no command runner", start)
	}

	// The package database. Its failure is the failure of the probe: without
	// it there is no inventory to report.
	out := c.run(dpkgQueryTool, []string{"-W", DpkgQueryFormat}, "dpkg-query-w")
	switch {
	case out.class != "":
		return c.fail(res, invStatusForClass(out.class), out.class,
			fmt.Sprintf("%s did not answer: %s", dpkgQueryTool, out.errText()), start)
	case out.exitCode != 0 && len(out.stdout) == 0:
		return c.fail(res, trustfreeze.StatusFailed, probe.ClassStartFailed,
			fmt.Sprintf("%s exited with status %d and printed nothing", dpkgQueryTool, out.exitCode), start)
	case out.exitCode != 0:
		c.warnPartial(probe.DiagFieldFailed, dpkgQueryTool,
			fmt.Sprintf("%s exited with status %d after printing %d byte(s); the inventory may be incomplete", dpkgQueryTool, out.exitCode, len(out.stdout)))
	}
	c.truncationCheck(dpkgQueryTool, out, "the package list is incomplete")
	pkgs, issues := ParseDpkgQuery(out.stdout)
	c.addIssues(dpkgQueryTool, issues)
	if len(pkgs) == 0 {
		c.warn(invDiagEmptyResult, dpkgQueryTool, "dpkg-query reported no package at all")
	}

	// The install reason. apt-mark is a separate tool: its absence costs one
	// attribute, not the probe.
	manual, manualKnown := c.aptMarkManual()

	dpkgVersion := c.toolVersion(dpkgQueryTool, "dpkg-query-version", ParseDpkgQueryVersion)
	aptVersion := ""
	if manualKnown {
		aptVersion = c.toolVersion(aptMarkTool, "apt-mark-version", ParseAptMarkVersion)
	}

	sources := []string{"command:dpkg-query -W"}
	if manualKnown {
		sources = append(sources, "command:apt-mark showmanual")
	}
	sort.Strings(sources)
	observed := trustfreeze.FormatTime(start)
	prov := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     sources,
		ObservedAt:  observed,
		ToolVersion: invToolVersionList([]string{dpkgQueryTool, aptMarkTool}, []string{dpkgVersion, aptVersion}),
	}

	arts := make([]trustfreeze.Artifact, 0, len(pkgs))
	for _, pkg := range pkgs {
		attrs := map[string]string{
			"name":         pkg.Name,
			"version":      pkg.Version,
			"architecture": pkg.Architecture,
			"manager":      "dpkg",
			"dpkg_status":  pkg.Status,
			"installed":    strconv.FormatBool(pkg.Installed()),
		}
		if manualKnown {
			// apt-mark prints a package without the multiarch qualifier on
			// this host, but it accepts and prints the qualified spelling
			// too, so both are looked up.
			attrs["install_reason"] = "automatic"
			if manual[pkg.Name] || manual[pkg.BaseName()] {
				attrs["install_reason"] = "manual"
			}
		}
		arts = append(arts, trustfreeze.Artifact{
			ID: ArtifactPackagePrefix + pkg.Name, Type: "package", Scope: "os", Source: PackagesProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityPublic,
		})
	}
	arts = append(arts, c.snapArtifacts(observed)...)
	arts = c.keepValid(arts)
	arts = c.capArtifacts(arts, maxPackageArtifacts, "package")
	return c.finish(res, arts, start)
}

// aptMarkManual returns the set of manually installed package names and
// whether apt-mark could be asked at all. The names apt-mark prints are not
// multiarch qualified, so they are matched against DpkgPackage.BaseName.
func (c *invCollector) aptMarkManual() (map[string]bool, bool) {
	out := c.run(aptMarkTool, []string{"showmanual"}, "apt-mark-showmanual")
	switch {
	case out.class == probe.ClassToolMissing:
		c.warnPartial(probe.DiagFieldUnavailable, "install_reason",
			"apt-mark was not found; whether a package was installed manually or pulled in as a dependency is not recorded")
		return nil, false
	case out.class != "":
		c.warnPartial(invDiagClassCode(out.class), "install_reason", "apt-mark showmanual: "+out.errText())
		return nil, false
	case out.exitCode != 0:
		c.warnPartial(probe.DiagFieldFailed, "install_reason",
			fmt.Sprintf("apt-mark showmanual exited with status %d; the install reason is not recorded", out.exitCode))
		return nil, false
	}
	c.truncationCheck(aptMarkTool, out, "the set of manually installed packages is incomplete")
	names := ParseAptMarkShowManual(out.stdout)
	manual := make(map[string]bool, len(names))
	for _, n := range names {
		manual[n] = true
	}
	return manual, true
}

// snapArtifacts reads the snap inventory when snapd is installed. A host
// without snap is not a host with a broken probe: the snap part is
// not_applicable with a reason and the probe stays captured (playbook L1).
func (c *invCollector) snapArtifacts(observed string) []trustfreeze.Artifact {
	if _, err := c.cc.Runner.LookPath(snapTool); err != nil {
		if probe.ErrorClass(err) == probe.ClassToolMissing {
			c.warn(probe.DiagFieldNotApplicable, snapTool,
				"snap is not installed on this host, so there is no snap inventory: not applicable, not empty")
			return nil
		}
		c.warnPartial(invDiagClassCode(probe.ErrorClass(err)), snapTool, "snap could not be resolved: "+err.Error())
		return nil
	}
	out := c.run(snapTool, []string{"list"}, "snap-list")
	switch {
	case out.class != "":
		c.warnPartial(invDiagClassCode(out.class), snapTool, "snap list: "+out.errText())
		return nil
	case out.exitCode != 0 && len(out.stdout) == 0:
		// A host with no snap installed and a host whose snapd does not
		// answer both exit non-zero with an empty stdout and differ only in
		// their message. No fixture of this set carries either message, so
		// the probe does not decide between them from invented text: it
		// reports that the snap inventory could not be established, keeps
		// the refusal as evidence and drops to partial (playbook L1).
		c.warnPartial(probe.DiagFieldFailed, snapTool,
			fmt.Sprintf("snap list exited with status %d and printed nothing; whether this host has no snap or snapd did not answer is not decidable from that, see the evidence of this run", out.exitCode))
		return nil
	case out.exitCode != 0:
		c.warnPartial(probe.DiagFieldFailed, snapTool,
			fmt.Sprintf("snap list exited with status %d after printing %d byte(s); the snap list may be incomplete", out.exitCode, len(out.stdout)))
	}
	c.truncationCheck(snapTool, out, "the snap list is incomplete")
	snaps, issues := ParseSnapList(out.stdout)
	c.addIssues(snapTool, issues)
	snapVersion := c.toolVersion(snapTool, "snap-version", ParseSnapVersion)
	prov := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     []string{"command:snap list"},
		ObservedAt:  observed,
		ToolVersion: invToolVersionList([]string{snapTool}, []string{snapVersion}),
	}
	truncated := 0
	arts := make([]trustfreeze.Artifact, 0, len(snaps))
	for _, s := range snaps {
		attrs := map[string]string{
			"name":      s.Name,
			"version":   s.Version,
			"revision":  s.Revision,
			"tracking":  s.Tracking,
			"publisher": s.Publisher,
			"manager":   "snap",
		}
		if s.Notes != "" && s.Notes != "-" {
			attrs["notes"] = s.Notes
		}
		if s.TrackingTruncated() {
			truncated++
		}
		arts = append(arts, trustfreeze.Artifact{
			ID: ArtifactSnapPrefix + s.Name, Type: "package", Scope: "os", Source: PackagesProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityPublic,
		})
	}
	if truncated > 0 {
		// snap list fits the tracking column to the terminal width and cuts
		// longer channels with a horizontal ellipsis. The recorded value is
		// then the tool's display form, not the full channel.
		c.warn(invDiagValueTruncatedByTool, "tracking",
			fmt.Sprintf("snap list shortened the tracking value of %d snap(s) to fit its column; the recorded value is what the tool printed", truncated))
	}
	return arts
}

// DpkgPackage is one record of the dpkg-query inventory call.
type DpkgPackage struct {
	// Name is ${binary:Package}: the package name, multiarch qualified where
	// dpkg qualifies it ("zlib1g:amd64").
	Name string
	// Version is ${Version}, epoch included ("1:1.3.dfsg-3.1ubuntu2.2").
	Version string
	// Architecture is ${Architecture}: "all", "amd64" and so on.
	Architecture string
	// Status is ${db:Status-Abbrev} without its trailing padding, for example
	// "ii" or "rc".
	Status string
}

// BaseName is the package name without the multiarch qualifier, which is how
// apt-mark names a package.
func (p DpkgPackage) BaseName() string {
	if i := strings.IndexByte(p.Name, ':'); i >= 0 {
		return p.Name[:i]
	}
	return p.Name
}

// Installed reports whether the package is installed right now.
// db:Status-Abbrev is three characters: desired action, current status, error
// flag. Only current status "i" is installed; "c" is the "rc" of a removed
// package whose configuration files are still on disk, which is state worth
// recording but not an installed package.
func (p DpkgPackage) Installed() bool { return len(p.Status) >= 2 && p.Status[1] == 'i' }

// SnapPackage is one row of snap list.
type SnapPackage struct {
	Name      string
	Version   string
	Revision  string
	Tracking  string
	Publisher string
	// Notes is the last column; snap prints "-" when there is none.
	Notes string
}

// snapEllipsis is the horizontal ellipsis snap appends to a value it had to
// shorten for its column width. It is written as an escape on purpose: a
// literal non-ASCII glyph in source is a lint finding.
const snapEllipsis = "…"

// TrackingTruncated reports whether snap shortened the tracking value.
func (s SnapPackage) TrackingTruncated() bool { return strings.HasSuffix(s.Tracking, snapEllipsis) }

// InventoryIssue is one record a parser of the inventory probes refused. The
// reason names the shape problem and never repeats the record itself, which
// could carry a name or a secret (playbook L4).
type InventoryIssue struct {
	// Line is the 1-based line number in the tool output.
	Line int
	// Reason is a short, content-free description of the shape problem.
	Reason string
}

// ParseDpkgQuery parses the output of the inventory call. Each line carries
// the four fields of DpkgQueryFormat, separated by tabs. Empty lines are
// ignored; every other line that does not have exactly four fields, or has no
// package name, becomes an issue and no artifact.
func ParseDpkgQuery(b []byte) ([]DpkgPackage, []InventoryIssue) {
	var (
		out    []DpkgPackage
		issues []InventoryIssue
	)
	for i, line := range invLines(b) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: fmt.Sprintf("expected 4 tab separated fields, found %d", len(fields))})
			continue
		}
		p := DpkgPackage{
			Name:         strings.TrimSpace(fields[0]),
			Version:      strings.TrimSpace(fields[1]),
			Architecture: strings.TrimSpace(fields[2]),
			Status:       strings.TrimSpace(fields[3]),
		}
		if p.Name == "" {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "empty package name"})
			continue
		}
		// A name that is not valid UTF-8 cannot become an artifact id and
		// cannot be written back as JSON either. It is an unparsable record,
		// and is reported as one instead of yielding an artifact with a
		// broken id.
		if !utf8.ValidString(p.Name) {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "package name is not valid UTF-8"})
			continue
		}
		out = append(out, p)
	}
	return out, issues
}

// ParseAptMarkShowManual parses the package names apt-mark showmanual prints,
// one per line. The result is sorted and free of duplicates, so it is a set.
func ParseAptMarkShowManual(b []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range invLines(b) {
		name := strings.TrimSpace(line)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ParseSnapList parses snap list. The first non-empty line is the header and
// is skipped by position, never by its words: snap translates the header and
// recomputes the column widths when a locale is set, so a parser that keys on
// the words or on fixed offsets breaks on the same host under another
// language. Rows are split on runs of whitespace, since no field of this
// table contains a space.
func ParseSnapList(b []byte) ([]SnapPackage, []InventoryIssue) {
	var (
		out    []SnapPackage
		issues []InventoryIssue
		header bool
	)
	for i, line := range invLines(b) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !header {
			header = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 6 {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: fmt.Sprintf("expected 6 whitespace separated columns, found %d", len(fields))})
			continue
		}
		out = append(out, SnapPackage{
			Name:      fields[0],
			Version:   fields[1],
			Revision:  fields[2],
			Tracking:  fields[3],
			Publisher: fields[4],
			Notes:     fields[5],
		})
	}
	return out, issues
}

// ParseDpkgQueryVersion reads the version out of "dpkg-query --version",
// whose first line ends in "... query tool version 1.22.6 (amd64)." The
// version is the field after the word "version". An output this parser does
// not recognize yields the empty string, which the caller reports as a
// diagnostic (playbook L7).
func ParseDpkgQueryVersion(b []byte) string {
	fields := strings.Fields(invFirstLine(b))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "version" {
			return strings.Trim(fields[i+1], ".")
		}
	}
	return ""
}

// ParseAptMarkVersion reads the version out of "apt-mark --version", whose
// only line is "apt 2.7.14 (amd64)".
func ParseAptMarkVersion(b []byte) string {
	fields := strings.Fields(invFirstLine(b))
	if len(fields) >= 2 && fields[0] == "apt" {
		return fields[1]
	}
	return ""
}

// ParseSnapVersion reads the client version out of "snap --version", a table
// whose first row is "snap <version>". The snapd row is a different fact (the
// daemon) and is not what parsed the list.
func ParseSnapVersion(b []byte) string {
	for _, line := range invLines(b) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "snap" {
			return fields[1]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers shared by linux.packages and linux.users.
// ---------------------------------------------------------------------------

// invOutcome is what one tool call produced, after the runner has redacted it.
type invOutcome struct {
	stdout   []byte
	exitCode int
	// truncated says a byte cap cut the stream, and stdoutBytes is what the
	// tool printed before the cap, so a diagnostic can name both.
	truncated   bool
	stdoutBytes int64
	// class is empty when the process ran to an exit; otherwise it is the
	// command error class (tool_missing, permission_denied, timeout, ...).
	class string
	err   error
}

// errText is the redacted error text of a run that never produced an exit.
func (o invOutcome) errText() string {
	if o.err == nil {
		return o.class
	}
	return o.err.Error()
}

// invCollector gathers the tool records, diagnostics and partial reasons of
// one probe run.
type invCollector struct {
	ctx      context.Context
	cc       probe.CollectContext
	tools    []trustfreeze.ToolInvocation
	warnings []trustfreeze.Diagnostic
	// partial holds the reasons that cap the probe at partial, in the order
	// they were found.
	partial []string
	// issues counts the unparsed records already reported, so the per-record
	// diagnostics stay bounded.
	issues int
}

func invNewCollector(ctx context.Context, cc probe.CollectContext) *invCollector {
	return &invCollector{ctx: ctx, cc: cc}
}

// invBaseResult returns the result fields a probe fills before it collects.
// The engine overwrites the authoritative ones with what it observed itself.
func invBaseResult(id, version string, cc probe.CollectContext, start time.Time) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{
		ProbeID:      id,
		ProbeVersion: version,
		Support:      cc.Support.Record(),
		StartedAt:    trustfreeze.FormatTime(start),
		Privilege:    cc.Privilege,
	}
}

// run runs one command and keeps its output as evidence. Evidence names are
// "<base>.stdout" and "<base>.stderr"; an empty stream is not written, its
// size and exit code are in the tool record instead.
func (c *invCollector) run(exe string, args []string, evidenceBase string) invOutcome {
	res := c.cc.Runner.Run(c.ctx, probe.CommandRequest{Executable: exe, Args: args, Redactor: c.cc.Redactor})
	c.tools = append(c.tools, res.Invocation())
	out := invOutcome{exitCode: res.ExitCode, truncated: res.StdoutTruncated, stdoutBytes: res.StdoutBytes}
	switch {
	case res.Err != nil:
		out.class, out.err = probe.ErrorClass(res.Err), res.Err
		return out
	case res.RedactionFailed:
		out.class = probe.ClassRedactionFailed
		out.err = errors.New("output could not be redacted and was dropped")
		return out
	}
	out.stdout = res.Stdout.Bytes()
	if evidenceBase != "" {
		if len(out.stdout) > 0 {
			c.addEvidence(evidenceBase+".stdout", "stdout:"+exe, res.Stdout, res.StdoutTruncated)
		}
		if len(res.Stderr.Bytes()) > 0 {
			c.addEvidence(evidenceBase+".stderr", "stderr:"+exe, res.Stderr, res.StderrTruncated)
		}
	}
	return out
}

// toolVersion runs "<tool> --version" and parses it. An unreadable version is
// a diagnostic, never a guess (playbook L7). The version output is kept as
// evidence, so the claim is checkable.
func (c *invCollector) toolVersion(exe, evidenceBase string, parse func([]byte) string) string {
	out := c.run(exe, []string{"--version"}, evidenceBase)
	switch {
	case out.class != "":
		c.warn(invDiagToolVersionUnknown, exe, exe+" --version did not answer: "+out.errText())
		return ""
	case out.exitCode != 0:
		c.warn(invDiagToolVersionUnknown, exe, fmt.Sprintf("%s --version exited with status %d", exe, out.exitCode))
		return ""
	}
	v := parse(out.stdout)
	if v == "" {
		c.warn(invDiagToolVersionUnknown, exe, exe+" --version printed a version line this build does not recognize")
	}
	return v
}

// invToolVersionList renders the tool versions of an artifact as
// "dpkg-query 1.22.6, apt-mark 2.7.14". Tools whose version stayed unknown
// are left out; their diagnostic already says so.
func invToolVersionList(names, versions []string) string {
	var parts []string
	for i, n := range names {
		if i < len(versions) && versions[i] != "" {
			parts = append(parts, n+" "+versions[i])
		}
	}
	return strings.Join(parts, ", ")
}

func (c *invCollector) addEvidence(name, source string, data redact.Redacted, truncated bool) {
	if _, err := c.cc.AddEvidence(name, source, data, truncated); err != nil {
		c.warn(probe.DiagEvidenceDropped, "", name+": "+err.Error())
	}
}

func (c *invCollector) warn(code, field, msg string) {
	c.warnings = append(c.warnings, trustfreeze.Diagnostic{Code: code, Field: field, Message: msg})
}

// warnPartial records a diagnostic and caps the probe at partial.
func (c *invCollector) warnPartial(code, field, msg string) {
	c.warn(code, field, msg)
	for _, r := range c.partial {
		if r == msg {
			return
		}
	}
	c.partial = append(c.partial, msg)
}

// truncationCheck reports output a byte cap cut. A cut list is an incomplete
// list, so the probe drops to partial, and the diagnostic names the stream
// and the cap that cut it (see truncation.go).
func (c *invCollector) truncationCheck(tool string, out invOutcome, consequence string) {
	if !out.truncated {
		return
	}
	stdoutCap, _ := outputCap(c.cc)
	c.warnPartial(trustfreeze.DiagOutputTruncated, tool,
		truncationNote(tool, "stdout", len(out.stdout), out.stdoutBytes, stdoutCap, consequence))
}

// addIssues reports the records a parser refused, one diagnostic each up to
// invMaxIssueDiagnostics, then one diagnostic for the rest.
func (c *invCollector) addIssues(tool string, issues []InventoryIssue) {
	if len(issues) == 0 {
		return
	}
	listed := 0
	for _, is := range issues {
		if c.issues >= invMaxIssueDiagnostics {
			break
		}
		c.issues++
		listed++
		c.warn(invDiagRecordUnparsed, tool, fmt.Sprintf("%s output line %d: %s", tool, is.Line, is.Reason))
	}
	if rest := len(issues) - listed; rest > 0 {
		c.warn(invDiagRecordUnparsed, tool, fmt.Sprintf("%d further %s record(s) were not parsed and are not listed individually", rest, tool))
	}
	c.markPartial(fmt.Sprintf("%d %s record(s) could not be parsed", len(issues), tool))
}

// markPartial caps the probe at partial without adding a diagnostic.
func (c *invCollector) markPartial(reason string) {
	for _, r := range c.partial {
		if r == reason {
			return
		}
	}
	c.partial = append(c.partial, reason)
}

// keepValid drops artifacts whose id would be refused when the bundle is
// written, so the reason is named here instead of being a generic engine
// drop. Ids come from host data (a package or account name), so this is a
// real case, not a theoretical one.
func (c *invCollector) keepValid(arts []trustfreeze.Artifact) []trustfreeze.Artifact {
	seen := map[string]bool{}
	kept := arts[:0:0]
	for _, a := range arts {
		switch {
		case trustfreeze.ValidateArtifactID(a.ID) != nil:
			c.warnPartial(probe.DiagArtifactDropped, "", "an object name does not yield a usable artifact id and was dropped")
		case seen[a.ID]:
			c.warnPartial(probe.DiagArtifactDropped, "", "two objects yield the artifact id "+a.ID+"; only the first was kept")
		default:
			seen[a.ID] = true
			kept = append(kept, a)
		}
	}
	return kept
}

// capArtifacts enforces a volume cap. The list is sorted first, so the kept
// set is the same on two captures of an unchanged host (playbook L8).
func (c *invCollector) capArtifacts(arts []trustfreeze.Artifact, max int, kind string) []trustfreeze.Artifact {
	if len(arts) <= max {
		return arts
	}
	sort.SliceStable(arts, func(i, j int) bool { return arts[i].ID < arts[j].ID })
	dropped := len(arts) - max
	c.warnPartial(invDiagLimitExceeded, "",
		fmt.Sprintf("this host has %d %s objects, more than the per-probe limit of %d; %d were dropped after sorting by id", len(arts), kind, max, dropped))
	return arts[:max]
}

// fail closes a probe whose primary source did not answer. No artifact is
// emitted: a probe that could not read its source reports the reason, never
// an empty inventory (playbook L1).
func (c *invCollector) fail(res trustfreeze.ProbeResult, status trustfreeze.ProbeStatus, class, reason string, start time.Time) trustfreeze.ProbeResult {
	res.Status = status
	res.Reason = reason
	res.Error = &trustfreeze.ProbeError{Class: class, Message: reason}
	res.Tools = c.tools
	res.Warnings = c.warnings
	res.DurationMS = c.cc.Now().Sub(start).Milliseconds()
	return res
}

// finish closes a probe that read its primary source.
func (c *invCollector) finish(res trustfreeze.ProbeResult, arts []trustfreeze.Artifact, start time.Time) trustfreeze.ProbeResult {
	res.Status = trustfreeze.StatusCaptured
	if len(c.partial) > 0 {
		res.Status = trustfreeze.StatusPartial
		res.Reason = strings.Join(c.partial, "; ")
	}
	for i := range arts {
		if d, err := trustfreeze.ComputeArtifactDigest(arts[i]); err == nil {
			arts[i].Digest = d
		}
	}
	trustfreeze.SortArtifacts(arts)
	if len(arts) > 0 {
		res.NormalizedState = arts
	}
	res.Tools = c.tools
	res.Warnings = c.warnings
	res.DurationMS = c.cc.Now().Sub(start).Milliseconds()
	return res
}

// invStatusForClass maps a command error class to the honest probe status
// (playbook L1). A missing tool is unavailable, a refusal is
// permission_denied, and neither is ever the other.
func invStatusForClass(class string) trustfreeze.ProbeStatus {
	switch class {
	case probe.ClassToolMissing:
		return trustfreeze.StatusUnavailable
	case probe.ClassPermissionDenied:
		return trustfreeze.StatusPermissionDenied
	case probe.ClassTimeout:
		return trustfreeze.StatusTimeout
	}
	return trustfreeze.StatusFailed
}

// invDiagClassCode maps a command error class to the diagnostic code of a
// field that could not be read because of it.
func invDiagClassCode(class string) string {
	switch class {
	case probe.ClassToolMissing:
		return probe.DiagFieldUnavailable
	case probe.ClassPermissionDenied:
		return probe.DiagFieldPermissionDenied
	case probe.ClassTimeout:
		return probe.DiagFieldTimeout
	}
	return probe.DiagFieldFailed
}

// invLines splits tool output into lines, without the line terminators and
// without a final empty line. A trailing carriage return is removed, so the
// parsers do not depend on the line ending.
func invLines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

// invFirstLine returns the first line of b, trimmed.
func invFirstLine(b []byte) string {
	for _, line := range invLines(b) {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// invJoinNames renders a sorted name list for an artifact attribute. Beyond
// max names the list is cut and the caller is told how many were dropped, so
// an attribute cannot grow without bound.
func invJoinNames(names []string, max int) (string, int) {
	if len(names) <= max {
		return strings.Join(names, ","), 0
	}
	return strings.Join(names[:max], ","), len(names) - max
}
