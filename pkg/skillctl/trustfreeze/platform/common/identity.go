// Package common holds probes that exist on every platform. PR-1 has one:
// common.identity (SPEC-0467, SPEC-0471 TF06-R2), which reports the OS
// identity (device/os) and the host name (device/host).
//
// Each OS source is a pure parser plus a thin reader. The parsers live in
// per-OS files (osrelease.go, swvers.go, winversion_*.go) so that every OS
// path runs on any host against fixtures.
//
// Limits of the subject: in a container or under WSL, os-release describes
// the image or the distribution while uname -r reports the host or VM kernel
// (for example a "-microsoft-standard-WSL2" release), so device/os mixes two
// layers. A container host name is usually the container id, so the subject
// id changes per container, and on macOS the kernel host name can follow the
// network when no HostName is configured. Containers and WSL become subjects
// of their own in later packages (SPEC-0471 TF06-R4).
package common

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Identity probe constants.
const (
	IdentityProbeID      = "common.identity"
	IdentityProbeVersion = "1"
	ArtifactOS           = "device/os"
	ArtifactHost         = "device/host"
)

// Attribute names of device/os and device/host.
const (
	AttrOSFamily      = "os_family"
	AttrArch          = "arch"
	AttrOSName        = "os_name"
	AttrOSVersion     = "os_version"
	AttrOSBuild       = "os_build"
	AttrKernelRelease = "kernel_release"
	AttrHostname      = "hostname"
)

// Linux os-release locations (os-release(5)): the first takes precedence,
// the second is read only when the first does not exist.
const (
	OSReleasePath       = "/etc/os-release"
	UsrLibOSReleasePath = "/usr/lib/os-release"
)

// WindowsCurrentVersionKey is the registry key the Windows source reads.
const WindowsCurrentVersionKey = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// OSInfo is what an OS source reports. An empty field was not reported.
type OSInfo struct {
	Name          string
	Version       string
	Build         string
	KernelRelease string
}

// WindowsVersionReader reads the Windows version (winversion_windows.go
// reads the registry; winversion_other.go returns ErrNotApplicable).
type WindowsVersionReader interface {
	Read() (OSInfo, error)
}

// DiagValueDerived marks an attribute that is not a plain copy of its source
// value; the message states the rule that produced it (for example a
// Windows 11 host whose registry ProductName still says "Windows 10").
const DiagValueDerived = "value_derived"

// windowsDetailReader is implemented by the registry reader and its test
// double: besides the mapped fields it returns the raw value set and the
// derivation of each field, so the evidence shows what the registry said.
type windowsDetailReader interface {
	readDetail() (windowsVersion, error)
}

// Source errors.
var (
	// ErrNotApplicable: the source does not exist on this platform.
	ErrNotApplicable = errors.New("common: not applicable on this platform")
	// ErrNoFields: a parser found no field at all.
	ErrNoFields = errors.New("common: no fields found")
)

// AllowedRoots returns the file roots the probes of this package read on
// goos. The capture engine passes them to the restricted file reader.
func AllowedRoots(goos string) []string {
	if goos == "linux" {
		return []string{OSReleasePath, UsrLibOSReleasePath}
	}
	return nil
}

// Register adds every probe of this package to reg.
func Register(reg *probe.Registry) error {
	return reg.Register(NewIdentityProbe())
}

// IdentityProbe is common.identity.
type IdentityProbe struct {
	// Windows reads the Windows version; nil means the source is missing.
	Windows WindowsVersionReader
}

// NewIdentityProbe returns the probe with the default Windows reader.
func NewIdentityProbe() *IdentityProbe {
	return &IdentityProbe{Windows: DefaultWindowsVersionReader()}
}

// Descriptor implements probe.Probe.
func (p *IdentityProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                IdentityProbeID,
		Version:           IdentityProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformDarwin, probe.PlatformLinux, probe.PlatformWindows},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    10 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactHost, ArtifactOS},
	}
}

// EvidenceClaims implements probe.EvidenceClaimer: every OS path is covered by
// fixture tests on any host, and the build compiles for every platform. Real
// platform runs are recorded outside the code (SPEC-0471 TF06-R7).
func (p *IdentityProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	levels := []probe.EvidenceLevel{probe.FixtureTested, probe.CrossCompiled}
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformDarwin:  levels,
		probe.PlatformLinux:   levels,
		probe.PlatformWindows: levels,
	}
}

// Support implements probe.Probe. Every source is optional per field, so the
// probe can always run on a declared platform; missing tools show up per
// field in Collect.
func (p *IdentityProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("no identity source for " + host.GOOS)
	}
	return probe.Supported()
}

// fieldState is the outcome of one field.
type fieldState int

const (
	fieldOK fieldState = iota
	fieldMissing
	fieldUnavailable
	fieldPermissionDenied
	fieldTimeout
	fieldFailed
	fieldNotApplicable
)

type fieldOutcome struct {
	value  string
	state  fieldState
	detail string
	// redactionFailed marks a field lost to a redaction failure.
	redactionFailed bool
}

// collector gathers the field outcomes of one Collect call.
type collector struct {
	ctx      context.Context
	cc       probe.CollectContext
	fields   map[string]*fieldOutcome
	sources  []string
	tools    []trustfreeze.ToolInvocation
	warnings []trustfreeze.Diagnostic
}

func (c *collector) set(name, value string, st fieldState, detail string) {
	c.fields[name] = &fieldOutcome{value: value, state: st, detail: detail}
}

// setAll sets every named field to the same failure state.
func (c *collector) setAll(names []string, st fieldState, detail string, redactionFailed bool) {
	for _, n := range names {
		c.fields[n] = &fieldOutcome{state: st, detail: detail, redactionFailed: redactionFailed}
	}
}

// setFromValue records a parsed value: present is ok, absent is missing, or
// not applicable when the field is optional on this OS.
func (c *collector) setFromValue(name, value, source string, optional bool) {
	switch {
	case strings.TrimSpace(value) != "":
		c.set(name, strings.TrimSpace(value), fieldOK, "")
	case optional:
		c.set(name, "", fieldNotApplicable, source+" does not define it on this system")
	default:
		c.set(name, "", fieldMissing, source+" did not report it")
	}
}

func (c *collector) addSource(s string) {
	for _, x := range c.sources {
		if x == s {
			return
		}
	}
	c.sources = append(c.sources, s)
}

func (c *collector) anyOSFieldRead() bool {
	for _, n := range []string{AttrOSName, AttrOSVersion, AttrOSBuild, AttrKernelRelease} {
		if f := c.fields[n]; f != nil && f.state == fieldOK {
			return true
		}
	}
	return false
}

func (c *collector) warn(code, field, msg string) {
	c.warnings = append(c.warnings, trustfreeze.Diagnostic{Code: code, Field: field, Message: msg})
}

// Collect implements probe.Probe.
func (p *IdentityProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := &collector{ctx: ctx, cc: cc, fields: map[string]*fieldOutcome{}}
	method := ""
	switch cc.GOOS {
	case "linux":
		method = "file"
		c.collectLinux()
		c.collectUname()
		c.collectMachine(false)
	case "darwin":
		method = "command"
		c.collectDarwin()
		c.collectUname()
		c.collectMachine(true)
	case "windows":
		method = "registry"
		c.collectWindows(p.Windows)
		c.set(AttrKernelRelease, "", fieldNotApplicable, "windows has no uname kernel release; the build is in os_build")
		c.collectWindowsMachine(p.Windows)
	default:
		res := p.baseResult(cc, start)
		res.Status = trustfreeze.StatusUnsupported
		res.Reason = "no identity source for " + cc.GOOS
		return res
	}
	c.collectHostname()
	return p.result(cc, c, method, start)
}

func (p *IdentityProbe) baseResult(cc probe.CollectContext, start time.Time) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{
		ProbeID:      IdentityProbeID,
		ProbeVersion: IdentityProbeVersion,
		Support:      cc.Support.Record(),
		StartedAt:    trustfreeze.FormatTime(start),
		Privilege:    cc.Privilege,
	}
}

var osFields = []string{AttrOSName, AttrOSVersion, AttrOSBuild}

// collectLinux reads os-release (os-release(5) precedence) through the
// restricted file reader, redacts it, keeps it as evidence and parses it.
func (c *collector) collectLinux() {
	path := OSReleasePath
	raw, err := c.cc.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		path = UsrLibOSReleasePath
		raw, err = c.cc.ReadFile(path)
	}
	if err != nil {
		st, detail := fileErrorState(err)
		c.setAll(osFields, st, "os-release: "+detail, false)
		return
	}
	rr, err := c.cc.Redactor.RedactBytes(c.ctx, redact.EvidenceDescriptor{ProbeID: IdentityProbeID, Name: "os-release", Source: "file:" + path}, raw)
	if err != nil {
		c.setAll(osFields, fieldFailed, "os-release could not be redacted and was dropped", true)
		return
	}
	c.addEvidence("os-release", "file:"+path, rr.Data, false)
	data, err := ParseOSReleaseData(rr.Data.Bytes())
	if err != nil {
		c.setAll(osFields, fieldFailed, "os-release: "+err.Error(), false)
		return
	}
	info := data.Info()
	c.addSource("file:" + path)
	// A key whose only assignment is malformed failed; it is not missing.
	// The issue carries no line content, so its detail is safe to persist.
	broken := map[string]OSReleaseIssue{}
	for _, is := range data.Issues {
		if _, seen := broken[is.Key]; is.Key != "" && !seen {
			broken[is.Key] = is
		}
	}
	set := func(attr, key, value, source string, optional bool) {
		if is, ok := broken[key]; ok && strings.TrimSpace(value) == "" {
			c.set(attr, "", fieldFailed, fmt.Sprintf("os-release line %d: %s", is.Line, is.Reason))
			return
		}
		c.setFromValue(attr, value, source, optional)
	}
	set(AttrOSName, osReleaseName, info.Name, "os-release NAME", false)
	if strings.TrimSpace(info.Version) == "" && strings.TrimSpace(info.Build) != "" {
		if _, ok := broken[osReleaseVersionID]; !ok {
			// A rolling release (Arch: BUILD_ID=rolling) has no version by
			// design: not applicable, not missing (SPEC-0467
			// section 5.5). Debian testing,
			// which defines neither key, stays missing.
			c.set(AttrOSVersion, "", fieldNotApplicable, "rolling release: os-release defines BUILD_ID, no VERSION_ID")
		} else {
			set(AttrOSVersion, osReleaseVersionID, info.Version, "os-release VERSION_ID", false)
		}
	} else {
		set(AttrOSVersion, osReleaseVersionID, info.Version, "os-release VERSION_ID", false)
	}
	// BUILD_ID is optional in os-release(5); most distributions omit it.
	set(AttrOSBuild, osReleaseBuildID, info.Build, "os-release BUILD_ID", true)
}

// collectDarwin runs sw_vers.
func (c *collector) collectDarwin() {
	out, st, detail, redFail := c.run("sw_vers", nil, "sw_vers.stdout")
	if st != fieldOK {
		c.setAll(osFields, st, "sw_vers: "+detail, redFail)
		return
	}
	info, err := ParseSwVers(out)
	if err != nil {
		c.setAll(osFields, fieldFailed, "sw_vers: "+err.Error(), false)
		return
	}
	c.addSource("command:sw_vers")
	c.setFromValue(AttrOSName, info.Name, "sw_vers ProductName", false)
	c.setFromValue(AttrOSVersion, info.Version, "sw_vers ProductVersion", false)
	c.setFromValue(AttrOSBuild, info.Build, "sw_vers BuildVersion", false)
}

// collectUname runs "uname -r" for the kernel release.
func (c *collector) collectUname() {
	out, st, detail, redFail := c.run("uname", []string{"-r"}, "uname-r.stdout")
	if st != fieldOK {
		c.fields[AttrKernelRelease] = &fieldOutcome{state: st, detail: "uname -r: " + detail, redactionFailed: redFail}
		return
	}
	c.addSource("command:uname -r")
	c.setFromValue(AttrKernelRelease, firstLine(out), "uname -r", false)
}

// collectMachine reads the machine architecture of the host from the OS
// ("uname -m"), never from the build of the collector (runtime.GOARCH): an
// amd64 build runs on an arm64 Mac under Rosetta 2, so the build target is
// not an observed fact about the device. On darwin a reported x86_64 is
// checked with sysctl.proc_translated, which is 1 for a process that Rosetta
// translates; the architecture is then arm64 and a value_derived diagnostic
// states the rule. The value is spelled like GOARCH (NormalizeMachine); the
// evidence keeps what uname printed.
func (c *collector) collectMachine(darwin bool) {
	out, st, detail, redFail := c.run("uname", []string{"-m"}, "uname-m.stdout")
	if st != fieldOK {
		c.fields[AttrArch] = &fieldOutcome{state: st, detail: "uname -m: " + detail, redactionFailed: redFail}
		return
	}
	c.addSource("command:uname -m")
	raw := firstLine(out)
	if raw == "" {
		c.set(AttrArch, "", fieldMissing, "uname -m did not report it")
		return
	}
	arch := NormalizeMachine(raw)
	if darwin && arch == "amd64" {
		translated, st, detail := c.rosettaTranslated()
		if st != fieldOK {
			c.set(AttrArch, "", st, "sysctl.proc_translated: "+detail)
			return
		}
		if translated {
			arch = "arm64"
			c.warn(DiagValueDerived, AttrArch, "uname -m reports "+raw+" inside Rosetta 2 translation; sysctl.proc_translated is 1, so the machine is arm64")
		}
	}
	c.set(AttrArch, arch, fieldOK, "")
}

// rosettaTranslated asks sysctl.proc_translated whether this process runs
// under Rosetta 2. The oid exists only on Apple silicon, so an Intel Mac
// answers "unknown oid": not translated. Any other outcome that is not "0"
// or "1" leaves the question open (a failed field, never a guess).
func (c *collector) rosettaTranslated() (bool, fieldState, string) {
	res := c.cc.Runner.Run(c.ctx, probe.CommandRequest{Executable: "sysctl", Args: []string{"-n", "sysctl.proc_translated"}, Redactor: c.cc.Redactor})
	c.tools = append(c.tools, res.Invocation())
	switch {
	case res.Err != nil:
		return false, commandErrorState(res.Err), res.Err.Error()
	case res.RedactionFailed:
		return false, fieldFailed, "output could not be redacted and was dropped"
	case res.ExitCode != 0:
		if bytes.Contains(res.Stderr.Bytes(), []byte("unknown oid")) {
			return false, fieldOK, ""
		}
		return false, fieldFailed, fmt.Sprintf("exit status %d", res.ExitCode)
	}
	c.addEvidence("sysctl-proc-translated.stdout", "stdout:sysctl", res.Stdout, res.StdoutTruncated)
	c.addSource("command:sysctl -n sysctl.proc_translated")
	switch firstLine(res.Stdout.Bytes()) {
	case "1":
		return true, fieldOK, ""
	case "0":
		return false, fieldOK, ""
	}
	return false, fieldFailed, "unexpected output"
}

// NormalizeMachine spells a machine name the way GOARCH does, so the same
// hardware reads the same on every OS: x86_64 is amd64, aarch64 is arm64,
// i386 to i686 are 386, 32-bit ARM names are arm, loongarch64 is loong64.
// Any other name is kept, in lower case.
func NormalizeMachine(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	switch m {
	case "x86_64", "amd64", "x64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i486", "i586", "i686", "x86":
		return "386"
	case "arm", "armv6l", "armv7l", "armv7", "armv8l", "armhf":
		return "arm"
	case "loongarch64":
		return "loong64"
	}
	return m
}

// windowsMachineReader is implemented by the default Windows reader and its
// test doubles: the native machine architecture of the host (on Windows
// IsWow64Process2, which reports the native machine also to an emulated x64
// or x86 process). ErrNotApplicable means there is no such source here.
type windowsMachineReader interface {
	nativeArch() (string, error)
}

// collectWindowsMachine reads the native machine architecture through the
// injected reader, never runtime.GOARCH.
func (c *collector) collectWindowsMachine(r WindowsVersionReader) {
	mr, ok := r.(windowsMachineReader)
	if !ok {
		c.set(AttrArch, "", fieldUnavailable, "no native machine source")
		return
	}
	arch, err := mr.nativeArch()
	switch {
	case errors.Is(err, ErrNotApplicable):
		c.set(AttrArch, "", fieldNotApplicable, "the windows native machine source does not exist on this platform")
	case err != nil:
		st, detail := fileErrorState(err)
		c.set(AttrArch, "", st, "native machine: "+detail)
	default:
		c.addSource("win32:IsWow64Process2")
		c.setFromValue(AttrArch, arch, "IsWow64Process2", false)
	}
}

// collectWindows reads the registry through the injected reader.
func (c *collector) collectWindows(r WindowsVersionReader) {
	if r == nil {
		c.setAll(osFields, fieldUnavailable, "no windows version reader", false)
		return
	}
	var (
		info    OSInfo
		err     error
		raw     map[string]string
		derived map[string]string
	)
	if dr, ok := r.(windowsDetailReader); ok {
		var v windowsVersion
		v, err = dr.readDetail()
		info, raw, derived = v.Info, v.Values, v.Derived
	} else {
		info, err = r.Read()
	}
	// A per-field error is attributed per field below; any other error with
	// nothing read applies to every field.
	var ve *winVersionError
	perField := errors.As(err, &ve)
	if err != nil && info == (OSInfo{}) && !perField {
		st, detail := fileErrorState(err)
		if errors.Is(err, ErrNotApplicable) {
			st, detail = fieldNotApplicable, "the windows registry does not exist on this platform"
		}
		c.setAll(osFields, st, "registry: "+detail, false)
		return
	}
	values := map[string]string{AttrOSName: info.Name, AttrOSVersion: info.Version, AttrOSBuild: info.Build}
	red, _, rerr := c.cc.Redactor.RedactValue(c.ctx, redact.ValueContext{ProbeID: IdentityProbeID, Path: "registry"}, values)
	if rerr != nil {
		c.setAll(osFields, fieldFailed, "registry values could not be redacted and were dropped", true)
		return
	}
	values, ok := red.(map[string]string)
	if !ok {
		c.setAll(osFields, fieldFailed, "registry values changed type during redaction", true)
		return
	}
	// The evidence is the value set the registry returned, when the reader
	// exposes it, so a Windows 11 capture still shows the registry's own
	// ProductName; otherwise the mapped fields.
	var evidence any = values
	if len(raw) > 0 {
		if rv, _, rerr := c.cc.Redactor.RedactValue(c.ctx, redact.ValueContext{ProbeID: IdentityProbeID, Path: "registry"}, raw); rerr == nil {
			evidence = rv
		} else {
			evidence = nil
			c.warn(trustfreeze.DiagRedactionFailed, "", "registry value set could not be redacted; evidence dropped")
		}
	}
	if evidence != nil {
		if b, merr := trustfreeze.MarshalFile(evidence); merr == nil {
			if rr, rerr := c.cc.Redactor.RedactBytes(c.ctx, redact.EvidenceDescriptor{ProbeID: IdentityProbeID, Name: "registry-currentversion.json"}, b); rerr == nil {
				c.addEvidence("registry-currentversion.json", "registry:"+WindowsCurrentVersionKey, rr.Data, false)
			}
		}
	}
	c.addSource("registry:" + WindowsCurrentVersionKey)
	for _, name := range osFields {
		if values[name] == "" && err != nil {
			ferr := err
			if perField {
				ferr = ve.Field(name)
			}
			if ferr != nil {
				st, detail := fileErrorState(ferr)
				c.set(name, "", st, "registry: "+detail)
				continue
			}
		}
		c.setFromValue(name, values[name], "registry", false)
		if rule, ok := derived[name]; ok && values[name] != "" {
			c.warn(DiagValueDerived, name, rule)
		}
	}
}

// collectHostname records the host name (sensitivity internal,
// SPEC-0466 section 5.8).
func (c *collector) collectHostname() {
	if c.cc.Hostname == nil {
		c.set(AttrHostname, "", fieldUnavailable, "no hostname source")
		return
	}
	name, err := c.cc.Hostname()
	if err != nil {
		c.set(AttrHostname, "", fieldFailed, "hostname: "+err.Error())
		return
	}
	red, _, err := c.cc.Redactor.RedactString(c.ctx, name)
	if err != nil {
		c.fields[AttrHostname] = &fieldOutcome{state: fieldFailed, detail: "hostname could not be redacted and was dropped", redactionFailed: true}
		return
	}
	c.setFromValue(AttrHostname, red, "hostname", false)
}

// run runs one command and keeps its stdout as evidence.
func (c *collector) run(exe string, args []string, evidenceName string) ([]byte, fieldState, string, bool) {
	res := c.cc.Runner.Run(c.ctx, probe.CommandRequest{Executable: exe, Args: args, Redactor: c.cc.Redactor})
	c.tools = append(c.tools, res.Invocation())
	switch {
	case res.Err != nil:
		// A failed command whose output could not be redacted keeps its
		// redaction_failed diagnostic.
		return nil, commandErrorState(res.Err), res.Err.Error(), res.RedactionFailed
	case res.RedactionFailed:
		return nil, fieldFailed, "output could not be redacted and was dropped", true
	case res.ExitCode != 0:
		return nil, fieldFailed, fmt.Sprintf("exit status %d", res.ExitCode), false
	}
	c.addEvidence(evidenceName, "stdout:"+exe, res.Stdout, res.StdoutTruncated)
	return res.Stdout.Bytes(), fieldOK, "", false
}

func (c *collector) addEvidence(name, source string, data redact.Redacted, truncated bool) {
	if _, err := c.cc.AddEvidence(name, source, data, truncated); err != nil {
		c.warn(probe.DiagEvidenceDropped, "", name+": "+err.Error())
	}
}

func commandErrorState(err error) fieldState {
	switch {
	case errors.Is(err, probe.ErrToolMissing):
		return fieldUnavailable
	case errors.Is(err, probe.ErrPermissionDenied):
		return fieldPermissionDenied
	case errors.Is(err, probe.ErrTimeout):
		return fieldTimeout
	}
	return fieldFailed
}

func fileErrorState(err error) (fieldState, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fieldUnavailable, "source does not exist"
	case errors.Is(err, fs.ErrPermission):
		return fieldPermissionDenied, "permission denied"
	case errors.Is(err, context.DeadlineExceeded):
		return fieldTimeout, "timed out"
	}
	return fieldFailed, err.Error()
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// diagnostic codes per field state.
var stateCode = map[fieldState]string{
	fieldMissing:          trustfreeze.DiagFieldMissing,
	fieldUnavailable:      probe.DiagFieldUnavailable,
	fieldPermissionDenied: probe.DiagFieldPermissionDenied,
	fieldTimeout:          probe.DiagFieldTimeout,
	fieldFailed:           probe.DiagFieldFailed,
	fieldNotApplicable:    probe.DiagFieldNotApplicable,
}

// result turns the field outcomes into the probe result. Status precedence
// (SPEC-0467 section 5.5): any field blocked by privilege gives
// permission_denied, else any timed out gives timeout, else any whose tool is
// missing gives unavailable, else any missing or failed gives partial, else
// captured. Not applicable fields do not lower the status. Artifacts carry every
// field that was read, whatever the status.
func (p *IdentityProbe) result(cc probe.CollectContext, c *collector, method string, start time.Time) trustfreeze.ProbeResult {
	res := p.baseResult(cc, start)
	names := make([]string, 0, len(c.fields))
	for n := range c.fields {
		names = append(names, n)
	}
	sort.Strings(names)

	count := map[fieldState][]string{}
	for _, n := range names {
		f := c.fields[n]
		if f.state == fieldOK {
			continue
		}
		count[f.state] = append(count[f.state], n)
		c.warn(stateCode[f.state], n, f.detail)
		if f.redactionFailed {
			c.warn(trustfreeze.DiagRedactionFailed, n, "evidence dropped (fail-closed)")
		}
	}
	switch {
	case len(count[fieldPermissionDenied]) > 0:
		res.Status = trustfreeze.StatusPermissionDenied
		res.Reason = "permission denied for " + strings.Join(count[fieldPermissionDenied], ", ")
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassPermissionDenied, Message: res.Reason}
	case len(count[fieldTimeout]) > 0:
		res.Status = trustfreeze.StatusTimeout
		res.Reason = "timed out reading " + strings.Join(count[fieldTimeout], ", ")
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTimeout, Message: res.Reason}
	case len(count[fieldUnavailable]) > 0:
		res.Status = trustfreeze.StatusUnavailable
		res.Reason = "source missing for " + strings.Join(count[fieldUnavailable], ", ")
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassToolMissing, Message: res.Reason}
	case len(count[fieldMissing])+len(count[fieldFailed]) > 0:
		res.Status = trustfreeze.StatusPartial
		res.Reason = "not read: " + strings.Join(append(append([]string{}, count[fieldMissing]...), count[fieldFailed]...), ", ")
	default:
		res.Status = trustfreeze.StatusCaptured
	}
	// Only GOOS and at most the architecture, no OS field from any source:
	// that is not an observed identity, whatever the per-field states say
	// (for example a windows host context with the non-windows registry
	// stub).
	if res.Status == trustfreeze.StatusCaptured && !c.anyOSFieldRead() {
		res.Status = trustfreeze.StatusUnsupported
		res.Reason = "no OS identity source is available for " + cc.GOOS + " in this build"
	}

	observed := trustfreeze.FormatTime(start)
	// os_family is GOOS: a binary runs only on the OS it was built for. The
	// architecture is not taken from the build (GOARCH), only from an OS
	// source (collectMachine, collectWindowsMachine), because emulation runs
	// a build on a machine of another architecture.
	osAttrs := map[string]string{AttrOSFamily: cc.GOOS}
	for _, n := range []string{AttrArch, AttrOSName, AttrOSVersion, AttrOSBuild, AttrKernelRelease} {
		if f := c.fields[n]; f != nil && f.state == fieldOK {
			osAttrs[n] = f.value
		}
	}
	sources := append([]string{"runtime:GOOS"}, c.sources...)
	sort.Strings(sources)
	arts := []trustfreeze.Artifact{{
		ID: ArtifactOS, Type: "os", Scope: "device", Source: IdentityProbeID,
		State:       trustfreeze.StateObserved,
		Attributes:  osAttrs,
		Provenance:  trustfreeze.Provenance{Method: method, Confidence: trustfreeze.ConfidenceProven, Sources: sources, ObservedAt: observed},
		Sensitivity: trustfreeze.SensitivityPublic,
	}}
	if f := c.fields[AttrHostname]; f != nil && f.state == fieldOK {
		arts = append(arts, trustfreeze.Artifact{
			ID: ArtifactHost, Type: "host", Scope: "device", Source: IdentityProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  map[string]string{AttrHostname: f.value},
			Provenance:  trustfreeze.Provenance{Method: "runtime", Confidence: trustfreeze.ConfidenceProven, Sources: []string{"runtime:hostname"}, ObservedAt: observed},
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	for i := range arts {
		if d, err := trustfreeze.ComputeArtifactDigest(arts[i]); err == nil {
			arts[i].Digest = d
		}
	}
	trustfreeze.SortArtifacts(arts)
	res.NormalizedState = arts
	res.Tools = c.tools
	res.Warnings = c.warnings
	res.DurationMS = cc.Now().Sub(start).Milliseconds()
	return res
}
