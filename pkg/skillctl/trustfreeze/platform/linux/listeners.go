package linux

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// linux.network.listeners reports every listening socket of the host from
// "ss -H -lntup" (SPEC-0471 TF06-R3). A listener bound to 0.0.0.0, to :: or
// to the address wildcard "*" is reachable from outside the host and is the
// finding a bastion is built around; one bound to a loopback address is not.
//
// Two properties of ss decide the honest status (SPEC-0471 TF06-R2). The
// owner column "users:((...))" is filled only for the caller's own processes
// unless the capture runs with privileges, so an unprivileged run knows the
// listening address of every socket but the owning process of almost none:
// that is a partial result with a named gap, never a captured one. And the
// pid inside that column changes on every restart of an unchanged service,
// so it is recorded under the attribute key "pid", which the normalization
// rule set drops before two bundles are compared; the program name stays.
const (
	// ListenersProbeID is the probe id of the listening socket probe.
	ListenersProbeID = "linux.network.listeners"
	// ListenersProbeVersion changes whenever the output of the probe can
	// change.
	ListenersProbeVersion = "1"
	// ListenersTool is the executable the probe runs.
	ListenersTool = "ss"
)

// listenersMaxRecords bounds the listener artifacts of one capture, and
// listenersMaxValueBytes bounds one attribute value that comes from the host
// (playbook L6). ss prints the process name as the kernel holds it, which a
// process can set to any length; every other family of this package caps its
// values the same way.
const (
	listenersMaxRecords    = 4096
	listenersMaxValueBytes = 200
)

// Artifact ids of the listener probe. The per listener id is
// "network/listener/<proto>/<address>/<port>", with an IPv6 address in
// brackets exactly as ss prints it.
const (
	ArtifactListeners       = "network/listeners"
	ArtifactListenerPrefix  = "network/listener"
	artifactTypeListener    = "listener"
	artifactTypeListenerSet = "listener-set"
)

// Exposure classes of a listening address. They say how far a socket can be
// reached, not how dangerous it is: severity belongs to the policy, never to
// a probe.
const (
	// ExposureLoopback: reachable only from the host itself.
	ExposureLoopback = "loopback"
	// ExposureLinkLocal: reachable from the local link only.
	ExposureLinkLocal = "link_local"
	// ExposureAnyAddress: bound to 0.0.0.0, to :: or to the wildcard "*",
	// so reachable through every address of the host.
	ExposureAnyAddress = "any_address"
	// ExposureSpecificAddress: bound to one concrete address of the host.
	ExposureSpecificAddress = "specific_address"
	// ExposureNone: the object publishes nothing beyond the host.
	ExposureNone = "none"
	// ExposureUnknown: the address could not be classified.
	ExposureUnknown = "unknown"
)

// Address families of a listening address.
const (
	familyIPv4        = "ipv4"
	familyIPv6        = "ipv6"
	familyUnspecified = "unspecified"
)

// ListenerProcess is one process ss named as the owner of a socket. PID is
// kept as the string ss printed and is volatile.
type ListenerProcess struct {
	Name string
	PID  string
}

// Listener is one listening socket as ss reported it. Address carries no
// brackets and no zone; the zone (the part after "%", for example "lo") is
// kept apart so that the artifact id can be rebuilt from the parts.
type Listener struct {
	// Proto is the ss Netid column, for example "tcp" or "udp".
	Proto string
	// SocketState is the ss State column, for example "LISTEN" or "UNCONN".
	SocketState string
	Address     string
	Zone        string
	Port        string
	Exposure    string
	Family      string
	// Processes is empty when ss did not report an owner, which is the
	// normal unprivileged case for a socket of another user.
	Processes []ListenerProcess
}

// OwnerKnown reports whether ss named an owning process for this socket.
func (l Listener) OwnerKnown() bool { return len(l.Processes) > 0 }

// ArtifactID returns the artifact id of the listener.
func (l Listener) ArtifactID() string {
	return ListenerArtifactID(l.Proto, l.Address, l.Zone, l.Port)
}

// ListenerArtifactID builds the stable id of a listening socket:
// "network/listener/<proto>/<address>/<port>". An address that carries a
// colon is an IPv6 address and is written in brackets, so the id segment can
// never start with a letter followed by a colon (which the core rejects as a
// drive letter) and so that the same socket seen through another tool, for
// example a published container port, yields the same id.
func ListenerArtifactID(proto, address, zone, port string) string {
	return ArtifactListenerPrefix + "/" + proto + "/" + listenerAddressSegment(address, zone) + "/" + port
}

func listenerAddressSegment(address, zone string) string {
	a := address
	if zone != "" {
		a += "%" + zone
	}
	if strings.Contains(address, ":") {
		a = "[" + a + "]"
	}
	return a
}

// ClassifyExposure returns the exposure class of a listening address as a
// tool printed it, with or without brackets and with or without a zone.
func ClassifyExposure(address string) string {
	addr, _ := splitAddressZone(address)
	switch addr {
	case "":
		return ExposureUnknown
	case "*":
		// ss prints "*" for a socket that is bound to no particular
		// address, which reaches as far as 0.0.0.0 or :: do.
		return ExposureAnyAddress
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ExposureUnknown
	}
	switch {
	case ip.IsUnspecified():
		return ExposureAnyAddress
	case ip.IsLoopback():
		return ExposureLoopback
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return ExposureLinkLocal
	}
	return ExposureSpecificAddress
}

// addressFamily returns the family of an address token.
func addressFamily(address string) string {
	addr, _ := splitAddressZone(address)
	switch {
	case addr == "" || addr == "*":
		return familyUnspecified
	case strings.Contains(addr, ":"):
		return familyIPv6
	case strings.Contains(addr, "."):
		return familyIPv4
	}
	return familyUnspecified
}

// splitAddressZone strips the brackets of an IPv6 address and separates the
// zone: "[fe80::1%eth0]" becomes "fe80::1" and "eth0".
func splitAddressZone(address string) (addr, zone string) {
	a := strings.TrimSpace(address)
	if strings.HasPrefix(a, "[") && strings.HasSuffix(a, "]") {
		a = a[1 : len(a)-1]
	}
	if i := strings.IndexByte(a, '%'); i >= 0 {
		return a[:i], a[i+1:]
	}
	return a, ""
}

// ssProcessPattern matches one entry of the ss owner column, for example
// ("svc-app-exporte",pid=2698,fd=6). The process name may contain a space,
// so the column is matched, never split on whitespace.
var ssProcessPattern = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

// ParseSSListeners parses the output of "ss -H -lntup". It is pure: it reads
// bytes and returns listeners plus one diagnostic per line it could not
// read, so it is table tested from fixtures on any operating system.
//
// A row has six whitespace separated columns (netid, state, recv queue, send
// queue, local address and port, peer address and port) plus an optional
// seventh owner column. The last colon of the local column separates address
// from port, which is why an IPv6 address is printed in brackets.
func ParseSSListeners(b []byte) ([]Listener, []trustfreeze.Diagnostic) {
	var (
		out   []Listener
		diags []trustfreeze.Diagnostic
	)
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		// "ss -H" prints no header; a run without -H is still readable.
		if fields[0] == "Netid" || (fields[0] == "State" && len(fields) > 1 && fields[1] == "Recv-Q") {
			continue
		}
		if len(fields) < 6 {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   "listener",
				Message: fmt.Sprintf("line %d: %d columns, at least 6 expected", i+1, len(fields)),
			})
			continue
		}
		addr, port, ok := splitLocalEndpoint(fields[4])
		if !ok {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   "listener",
				Message: fmt.Sprintf("line %d: local endpoint has no port", i+1),
			})
			continue
		}
		address, zone := splitAddressZone(addr)
		l := Listener{
			Proto:       fields[0],
			SocketState: fields[1],
			Address:     address,
			Zone:        zone,
			Port:        port,
			Exposure:    ClassifyExposure(addr),
			Family:      addressFamily(addr),
		}
		if len(fields) > 6 {
			owner := strings.Join(fields[6:], " ")
			for _, m := range ssProcessPattern.FindAllStringSubmatch(owner, -1) {
				l.Processes = append(l.Processes, ListenerProcess{Name: m[1], PID: m[2]})
			}
			if len(l.Processes) == 0 {
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    netDiagRecordUnparsed,
					Field:   "listener_process",
					Message: fmt.Sprintf("line %d: the owner column could not be read", i+1),
				})
			}
			sort.Slice(l.Processes, func(x, y int) bool {
				if l.Processes[x].Name != l.Processes[y].Name {
					return l.Processes[x].Name < l.Processes[y].Name
				}
				return l.Processes[x].PID < l.Processes[y].PID
			})
		}
		out = append(out, l)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ArtifactID() < out[j].ArtifactID() })
	return out, diags
}

// splitLocalEndpoint splits "address:port" at the last colon. The address
// keeps its brackets and its zone for the caller to strip.
func splitLocalEndpoint(s string) (addr, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ListenersProbe collects the listening sockets of a Linux host.
type ListenersProbe struct{}

// NewListenersProbe returns the probe.
func NewListenersProbe() *ListenersProbe { return &ListenersProbe{} }

// Descriptor implements probe.Probe.
func (p *ListenersProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                ListenersProbeID,
		Version:           ListenersProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    15 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactListenerPrefix, ArtifactListeners},
	}
}

// RequiredTools implements the optional tool interface of the capture
// package: doctor resolves these names and never runs them.
func (p *ListenersProbe) RequiredTools() []string { return []string{ListenersTool} }

// EvidenceClaims implements probe.EvidenceClaimer. The parsers are covered
// by fixture tests that run on any host, and the package compiles for Linux.
// Whether the probe ran on a real Linux host is not decided in code
// (SPEC-0471 TF06-R7).
func (p *ListenersProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe: availability only, nothing is collected.
func (p *ListenersProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("ss is a Linux tool; no listener source for " + host.GOOS)
	}
	return netLookTool(host, ListenersTool, "the listening sockets of this host cannot be read without "+ListenersTool)
}

// Collect implements probe.Probe.
func (p *ListenersProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	s := newNetProbeState(ctx, cc)
	res := s.base(ListenersProbeID, ListenersProbeVersion, start)
	version := s.toolVersion(ListenersTool, []string{"-V"}, "ss-version.stdout")

	cmd := s.run(ListenersTool, []string{"-H", "-lntup"})
	if cmd.Status != trustfreeze.StatusCaptured {
		// No artifact at all: unlike an installed firewall backend or an
		// installed container runtime, the mere presence of ss says nothing
		// about the exposure of the host, and a set artifact with no count
		// would only look like a result. The status carries the fact.
		s.evidenceIfAny("ss-lntup.stderr", "stderr:ss", cmd.Res.Stderr, cmd.Res.StderrTruncated)
		res.Status, res.Reason = cmd.Status, "ss -H -lntup: "+cmd.Detail
		res.Error = &trustfreeze.ProbeError{Class: cmd.Class, Message: res.Reason}
		return s.finish(res, nil, start)
	}
	s.evidence("ss-lntup.stdout", "stdout:ss", cmd.Res.Stdout, cmd.Res.StdoutTruncated)
	// The cut has to be read before the rows are counted: a count over a cut
	// list is a claim about the host that nobody measured (F1).
	truncatedReason := s.truncationCheck(cmd, "listener_list",
		"the listening sockets beyond the cut are not in this bundle, and the recorded counts count only what was read")
	listeners, diags := ParseSSListeners(cmd.Res.Stdout.Bytes())
	s.warnings = append(s.warnings, diags...)
	capped := false
	if len(listeners) > listenersMaxRecords {
		s.warn(netDiagVolumeCapped, "listener",
			fmt.Sprintf("%d listening sockets; only the first %d are recorded as artifacts", len(listeners), listenersMaxRecords))
		capped = true
		listeners = listeners[:listenersMaxRecords]
	}

	observed := trustfreeze.FormatTime(start)
	prov := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     s.sourceList(),
		ObservedAt:  observed,
		ToolVersion: version,
	}
	counts := map[string]int{}
	ownerUnknown := 0
	seen := map[string]bool{}
	arts := make([]trustfreeze.Artifact, 0, len(listeners)+1)
	for _, l := range listeners {
		id := l.ArtifactID()
		if seen[id] {
			s.warn(probe.DiagArtifactDropped, "listener", "two listeners share the id "+id+"; the second was dropped")
			continue
		}
		seen[id] = true
		counts[l.Exposure]++
		attrs := map[string]string{
			"proto":          l.Proto,
			"local_address":  l.Address,
			"port":           l.Port,
			"exposure":       l.Exposure,
			"address_family": l.Family,
			"socket_state":   l.SocketState,
		}
		if l.Zone != "" {
			attrs["zone"] = l.Zone
		}
		if l.OwnerKnown() {
			names := make([]string, 0, len(l.Processes))
			pids := make([]string, 0, len(l.Processes))
			for _, pr := range l.Processes {
				names = append(names, pr.Name)
				pids = append(pids, pr.PID)
			}
			processNames, nameCut := privCapList(names, listenersMaxValueBytes)
			if nameCut {
				s.warn(netDiagVolumeCapped, "process_name",
					"the process name of "+id+" is longer than "+strconv.Itoa(listenersMaxValueBytes)+" bytes and was cut")
			}
			attrs["process_name"] = processNames
			// The pid is volatile: the normalization rule set drops exactly
			// this attribute key before two bundles are compared, so a
			// restarted but otherwise unchanged service is not drift.
			attrs["pid"] = strings.Join(pids, ",")
			attrs["owner_known"] = "true"
		} else {
			ownerUnknown++
			attrs["owner_known"] = "false"
		}
		arts = append(arts, trustfreeze.Artifact{
			ID: id, Type: artifactTypeListener, Scope: "device", Source: ListenersProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	// The set artifact states the result even when it is empty, so an empty
	// listener list is a recorded fact and not an absence of records. Where
	// the output limit or the volume cap cut the list, the artifact says so
	// beside the counts, so no reader takes the count for the whole host.
	setAttrs := map[string]string{
		"listener_count":         strconv.Itoa(len(arts)),
		"any_address_count":      strconv.Itoa(counts[ExposureAnyAddress]),
		"link_local_count":       strconv.Itoa(counts[ExposureLinkLocal]),
		"loopback_count":         strconv.Itoa(counts[ExposureLoopback]),
		"specific_address_count": strconv.Itoa(counts[ExposureSpecificAddress]),
		"unknown_address_count":  strconv.Itoa(counts[ExposureUnknown]),
		"owner_unknown_count":    strconv.Itoa(ownerUnknown),
		"tool":                   ListenersTool,
	}
	if truncatedReason != "" || capped {
		setAttrs["listener_list_truncated"] = privBool(true)
	}
	arts = append(arts, trustfreeze.Artifact{
		ID: ArtifactListeners, Type: artifactTypeListenerSet, Scope: "device", Source: ListenersProbeID,
		State:       trustfreeze.StateObserved,
		Attributes:  setAttrs,
		Provenance:  prov,
		Sensitivity: trustfreeze.SensitivityPublic,
	})

	var reasons []string
	if truncatedReason != "" {
		reasons = append(reasons, truncatedReason)
	}
	if capped {
		reasons = append(reasons, fmt.Sprintf("more than %d listening sockets; the rest is not recorded", listenersMaxRecords))
	}
	if ownerUnknown > 0 {
		s.warn(probe.DiagFieldPermissionDenied, "listener_process",
			fmt.Sprintf("ss named no owning process for %d of %d listeners; unprivileged ss fills the users column only for the caller's own processes", ownerUnknown, len(arts)-1))
		reasons = append(reasons, fmt.Sprintf("the owning process is not observable for %d of %d listeners", ownerUnknown, len(arts)-1))
	}
	if len(diags) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d line(s) of ss output could not be read", len(diags)))
	}
	if len(reasons) > 0 {
		res.Status, res.Reason = trustfreeze.StatusPartial, strings.Join(reasons, "; ")
	} else {
		res.Status = trustfreeze.StatusCaptured
	}
	return s.finish(res, arts, start)
}

// Shared helpers of the three probes this file, firewall.go and
// containers.go implement. They live here because these three probes are
// written and reviewed together; nothing outside the package uses them.

// netDiagRecordUnparsed marks one record of tool output that a parser could
// not read. The record is lost, the rest of the result is not, and the probe
// is at most partial (SPEC-0471 TF06-R2).
const netDiagRecordUnparsed = "record_unparsed"

// netDiagEvidenceWithheld marks output that was deliberately not persisted
// as evidence because it can carry addresses that are personal data. The
// derived artifacts are persisted instead.
const netDiagEvidenceWithheld = "evidence_withheld"

// truncationCheck reports what a byte cap cut from the output of cmd. The
// returned reason is empty when nothing was cut; otherwise the caller adds it
// to the reasons that make the probe partial, and the diagnostic already
// names the stream and the cap (see truncation.go).
func (s *netProbeState) truncationCheck(cmd netCmd, field, consequence string) string {
	outCap, errCap := outputCap(s.cc)
	tool := cmd.Res.Executable
	var reason string
	if cmd.Res.StdoutTruncated {
		s.warn(trustfreeze.DiagOutputTruncated, field,
			truncationNote(tool, "stdout", len(cmd.Res.Stdout.Bytes()), cmd.Res.StdoutBytes, outCap, consequence))
		reason = consequence
	}
	if cmd.Res.StderrTruncated {
		s.warn(trustfreeze.DiagOutputTruncated, field,
			truncationNote(tool, "stderr", len(cmd.Res.Stderr.Bytes()), cmd.Res.StderrBytes, errCap,
				"the recorded cause of the failure is incomplete"))
	}
	return reason
}

// netCmd is the classified outcome of one command run. Status is captured
// when the tool answered with exit code 0; every other status is the honest
// class of the failure (SPEC-0471 TF06-R2).
type netCmd struct {
	Res    probe.CommandResult
	Status trustfreeze.ProbeStatus
	Class  string
	Detail string
}

// netProbeState accumulates what one Collect call produces besides its
// artifacts: the tool invocations, the diagnostics and the sources.
type netProbeState struct {
	ctx      context.Context
	cc       probe.CollectContext
	tools    []trustfreeze.ToolInvocation
	warnings []trustfreeze.Diagnostic
	sources  []string
}

func newNetProbeState(ctx context.Context, cc probe.CollectContext) *netProbeState {
	return &netProbeState{ctx: ctx, cc: cc}
}

func (s *netProbeState) warn(code, field, msg string) {
	s.warnings = append(s.warnings, trustfreeze.Diagnostic{Code: code, Field: field, Message: msg})
}

func (s *netProbeState) addSource(src string) {
	for _, x := range s.sources {
		if x == src {
			return
		}
	}
	s.sources = append(s.sources, src)
}

// sourceList returns the recorded sources, sorted.
func (s *netProbeState) sourceList() []string {
	out := append([]string(nil), s.sources...)
	sort.Strings(out)
	return out
}

// run executes one command through the injected runner and classifies the
// outcome. A non-zero exit whose stderr carries one of the refusals the
// tools print without root is permission_denied, never unavailable and never
// a silent empty result.
func (s *netProbeState) run(exe string, args []string) netCmd {
	res := s.cc.Runner.Run(s.ctx, probe.CommandRequest{Executable: exe, Args: args, Redactor: s.cc.Redactor})
	s.tools = append(s.tools, res.Invocation())
	out := netCmd{Res: res}
	switch {
	case res.Err != nil:
		out.Status, out.Class = netCommandStatus(res.Err), probe.ErrorClass(res.Err)
		out.Detail = res.Err.Error()
	case res.RedactionFailed:
		out.Status, out.Class = trustfreeze.StatusPartial, probe.ClassRedactionFailed
		out.Detail = "output could not be redacted and was dropped"
	case res.ExitCode != 0:
		out.Detail = netExitDetail(res)
		if netRefusedWithoutRoot(res.Stderr.Bytes()) {
			out.Status, out.Class = trustfreeze.StatusPermissionDenied, probe.ClassPermissionDenied
		} else {
			out.Status, out.Class = trustfreeze.StatusFailed, probe.ClassTerminated
		}
	default:
		out.Status = trustfreeze.StatusCaptured
		s.addSource("command:" + strings.TrimSpace(exe+" "+strings.Join(args, " ")))
	}
	return out
}

// netExitDetail describes a non-zero exit with the first line the tool
// printed on stderr, which is the line that names the cause.
func netExitDetail(res probe.CommandResult) string {
	d := fmt.Sprintf("exit status %d", res.ExitCode)
	if first := netFirstLine(res.Stderr.Bytes()); first != "" {
		d += ": " + first
	}
	return d
}

// netRefusedWithoutRoot reports whether stderr carries a refusal that a tool
// prints when it is run without the privileges it needs. The first two
// phrases are the ones the trial host produced verbatim: nft prints
// "Operation not permitted (you must be root)" and ufw prints "ERROR: You
// need to be root to run this script". The others are the shapes the same
// tools and the container clients print for a refused socket or file, which
// this host could not produce read-only.
func netRefusedWithoutRoot(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	for _, m := range []string{
		"operation not permitted",
		"you need to be root",
		"must be root",
		"permission denied",
		"access is denied",
		"not permitted",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// netCommandStatus maps a runner error to the honest probe status.
func netCommandStatus(err error) trustfreeze.ProbeStatus {
	switch probe.ErrorClass(err) {
	case probe.ClassToolMissing:
		return trustfreeze.StatusUnavailable
	case probe.ClassPermissionDenied:
		return trustfreeze.StatusPermissionDenied
	case probe.ClassTimeout:
		return trustfreeze.StatusTimeout
	}
	return trustfreeze.StatusFailed
}

// netDiagCode is the diagnostic code that belongs to a probe status.
func netDiagCode(st trustfreeze.ProbeStatus) string {
	switch st {
	case trustfreeze.StatusUnavailable:
		return probe.DiagFieldUnavailable
	case trustfreeze.StatusPermissionDenied:
		return probe.DiagFieldPermissionDenied
	case trustfreeze.StatusTimeout:
		return probe.DiagFieldTimeout
	case trustfreeze.StatusNotApplicable:
		return probe.DiagFieldNotApplicable
	}
	return probe.DiagFieldFailed
}

// netLookTool resolves one executable without running it, for Support.
func netLookTool(host probe.HostContext, exe, reason string) probe.SupportResult {
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if _, err := host.Runner.LookPath(exe); err != nil {
		switch probe.ErrorClass(err) {
		case probe.ClassPermissionDenied:
			return probe.PermissionDenied(exe + " is not executable by this account")
		default:
			return probe.Unavailable(exe + " was not found: " + reason)
		}
	}
	return probe.Supported()
}

// toolVersion runs the version command of a tool and returns its first line.
// A parser is valid only for the versions it was measured against, so an
// unknown version is a diagnostic, never a guess.
func (s *netProbeState) toolVersion(exe string, args []string, evidenceName string) string {
	cmd := s.run(exe, args)
	if cmd.Status != trustfreeze.StatusCaptured {
		s.warn(netDiagCode(cmd.Status), "tool_version", exe+" "+strings.Join(args, " ")+": "+cmd.Detail)
		return ""
	}
	// A few tools print their banner on stderr; both streams are redacted.
	out := cmd.Res.Stdout
	truncated := cmd.Res.StdoutTruncated
	if len(out.Bytes()) == 0 {
		out, truncated = cmd.Res.Stderr, cmd.Res.StderrTruncated
	}
	v := netFirstLine(out.Bytes())
	if v == "" {
		s.warn(trustfreeze.DiagFieldMissing, "tool_version", exe+" printed no version line")
		return ""
	}
	s.evidence(evidenceName, "stdout:"+exe, out, truncated)
	return v
}

// evidence hands redacted output to the evidence sink of the run.
func (s *netProbeState) evidence(name, source string, data redact.Redacted, truncated bool) {
	if _, err := s.cc.AddEvidence(name, source, data, truncated); err != nil {
		s.warn(probe.DiagEvidenceDropped, "", name+": "+err.Error())
	}
}

// evidenceIfAny persists output only when there is any.
func (s *netProbeState) evidenceIfAny(name, source string, data redact.Redacted, truncated bool) {
	if len(data.Bytes()) == 0 {
		return
	}
	s.evidence(name, source, data, truncated)
}

// base returns the skeleton result the engine fills in further.
func (s *netProbeState) base(id, version string, start time.Time) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{
		ProbeID:      id,
		ProbeVersion: version,
		Support:      s.cc.Support.Record(),
		StartedAt:    trustfreeze.FormatTime(start),
		Privilege:    s.cc.Privilege,
	}
}

// finish digests and sorts the artifacts and attaches tools, diagnostics and
// duration. Every list is sorted by a stable key, so two captures of an
// unchanged host produce the same bytes.
func (s *netProbeState) finish(res trustfreeze.ProbeResult, arts []trustfreeze.Artifact, start time.Time) trustfreeze.ProbeResult {
	for i := range arts {
		d, err := trustfreeze.ComputeArtifactDigest(arts[i])
		if err != nil {
			s.warn(probe.DiagArtifactDropped, arts[i].ID, "the artifact digest could not be computed: "+err.Error())
			continue
		}
		arts[i].Digest = d
	}
	trustfreeze.SortArtifacts(arts)
	res.NormalizedState = arts
	res.Tools = s.tools
	res.Warnings = s.warnings
	res.DurationMS = s.cc.Now().Sub(start).Milliseconds()
	return res
}

// netFirstLine returns the first non-empty line of b, trimmed.
func netFirstLine(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

// netSortedKeys returns the keys of m, sorted.
func netSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
