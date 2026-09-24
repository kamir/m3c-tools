package linux

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// linux.dns reports which resolver answers for this host (SPEC-0471 TF06-R3).
// A bastion that resolves through a server somebody else controls can be sent
// anywhere, so the resolver is part of the trust surface, and the two halves
// of the answer are not the same kind of fact.
//
// Declared versus observed (playbook L3), and this probe exists to keep the
// two apart:
//   - /etc/resolv.conf is what the host DECLARES. It is a file on disk; on a
//     systemd-resolved host it is a symlink to the stub file and says nothing
//     but "ask the local stub at 127.0.0.53". That is the state `declared`,
//     and it stays declared.
//   - "resolvectl status" is what systemd-resolved OBSERVES right now for each
//     link: the uplink servers it actually queries, the search domains in
//     force, the DNSSEC and DNSOverTLS mode. That is the state `observed`.
//
// The two live in separate artifacts and are never folded into one. A host
// whose resolv.conf names the stub while resolvectl names an uplink server is
// not inconsistent: those are two different statements, and a baseline that
// merged them would lose the only one a reader can check against the file.
//
// Why the human output and not a JSON one, measured on both hosts on
// 2026-09-24 rather than assumed: systemd 249 (Ubuntu 22.04.5) refuses
// "resolvectl --json=short status" with "unrecognized option" and exit 1, and
// systemd 255 (Ubuntu 24.04.1) ACCEPTS the flag, exits 0, and prints the same
// human text it prints without it. A probe that took an accepted flag for a
// JSON answer would hand human text to a JSON decoder on the newer of the two
// systems. There is therefore no JSON form of "status" to prefer, the probe
// parses the text, and it records the systemd version the text came from,
// because a parser is valid only for the versions it was measured against
// (playbook L7).
//
// The text itself is not column formatted either, which is the second reason
// nothing here counts characters: resolvectl right-aligns the labels, and the
// width it aligns to differs between the two versions (systemd 249 aligns per
// block, so the same label is indented differently in two blocks of one
// output; systemd 255 aligns the whole document to one width). Every line is
// therefore trimmed and split at its first colon.
const (
	// DNSProbeID is the probe id of the resolver probe.
	DNSProbeID = "linux.dns"
	// DNSProbeVersion changes whenever the output of the probe can change.
	DNSProbeVersion = "1"
	// DNSTool is the executable the probe runs.
	DNSTool = "resolvectl"
)

// DNSResolvConfPath is the declared resolver configuration of the host. On
// both measured hosts it is a symlink to
// ../run/systemd/resolve/stub-resolv.conf, which DNSAllowedRoots explains.
const DNSResolvConfPath = "/etc/resolv.conf"

// DNSAllowedRoots returns the file roots this probe reads: the one file, and
// nothing else.
//
// On both measured hosts /etc/resolv.conf is a symlink into
// /run/systemd/resolve, and probe.RootedFileReader checks the RESOLVED path
// against its roots as well, so the target has to be inside the allowed set
// for the read to succeed. It already is, without naming the directory:
// NewRootedFileReader adds the resolved form of every root it is given, so a
// root that is the symlink itself carries its target with it. Naming
// /run/systemd/resolve too would widen what this capture may open from one
// file to a whole directory of resolver state, for no measured gain (see
// dns_test.go, TestDNSAllowedRootsCoverTheSymlinkTarget).
func DNSAllowedRoots() []string { return []string{DNSResolvConfPath} }

// The stub addresses of systemd-resolved. 127.0.0.53 is the stub listener
// every client is pointed at; 127.0.0.54 is the proxy listener that bypasses
// the local cache. A resolv.conf naming either one delegates the real decision
// to systemd-resolved, which is why the file alone is never the whole answer.
const (
	dnsStubAddress  = "127.0.0.53"
	dnsProxyAddress = "127.0.0.54"
)

// Artifact ids of the resolver probe.
const (
	// ArtifactDNSResolver is the observed global resolver state.
	ArtifactDNSResolver = "dns/resolver"
	// ArtifactDNSLinkPrefix is the id prefix of one link's observed resolver
	// state: "dns/link/<interface name>".
	ArtifactDNSLinkPrefix = "dns/link"
	// ArtifactDNSResolvConf is the declared resolver configuration.
	ArtifactDNSResolvConf = "dns/resolv-conf"

	artifactTypeDNSResolver   = "dns-resolver"
	artifactTypeDNSLink       = "dns-link"
	artifactTypeDNSResolvConf = "dns-resolv-conf"
)

// Diagnostic codes of this probe.
const (
	// dnsDiagFieldUnread names the labels resolvectl printed that this build
	// does not record. It does not lower the status: every field the probe
	// declares was read, and a newer systemd that prints one more line is a
	// gap a reader should see rather than a failure of the capture.
	dnsDiagFieldUnread = "dns_field_unread"
	// dnsDiagResolverUnknown marks a host where the observed state could not
	// be established at all, so only the declared file is in the bundle.
	dnsDiagResolverUnknown = "dns_resolver_unobserved"
	// dnsDiagDirectiveUnread marks a resolv.conf directive this build does
	// not record.
	dnsDiagDirectiveUnread = "resolv_conf_directive_unread"
)

// dnsMaxValueBytes bounds one attribute value that comes from the host, and
// dnsMaxLinks bounds the link artifacts of one capture. A host running
// containers has one link per veth, which is why the second cap exists: the
// trial host printed 27 link blocks for one physical interface.
const (
	dnsMaxValueBytes = 400
	dnsMaxLinks      = 512
)

// The two values a tri-state field of this probe can take beside the empty
// string, which means the output did not say.
const (
	dnsYes = "yes"
	dnsNo  = "no"
)

// ResolverScope is the resolver state of one link, and of the global block,
// as resolvectl printed it. The global block prints no scopes and no current
// server, so those stay empty there; every other field has the same meaning
// in both places, which is why one type serves both.
type ResolverScope struct {
	// Name is the interface name, empty for the global block.
	Name string
	// Scopes are the "Current Scopes" entries, for example "DNS" or
	// "LLMNR/IPv4". A link with none prints the single word "none", which is
	// recorded as an empty list plus ScopesNone.
	Scopes []string
	// ScopesNone says resolvectl printed "none": the link resolves nothing.
	ScopesNone bool
	// DefaultRoute, LLMNR, MDNS and DNSOverTLS are "yes", "no" or empty when
	// the Protocols line did not mention them.
	DefaultRoute string
	LLMNR        string
	MDNS         string
	DNSOverTLS   string
	// DNSSECMode is the left half of "DNSSEC=no/unsupported" and
	// DNSSECSupport the right half.
	DNSSECMode    string
	DNSSECSupport string
	// CurrentDNSServer is the server this link queries at the moment.
	CurrentDNSServer string
	// DNSServers are all servers configured for this link, in the order
	// printed.
	DNSServers []string
	// SearchDomains are the "DNS Domain" entries that are search domains.
	SearchDomains []string
	// RoutingOnlyDomains are the "DNS Domain" entries that start with "~":
	// they route queries for a domain to this link without being appended to
	// a short name, and "~." is the entry that makes a link the one that
	// answers everything.
	RoutingOnlyDomains []string
}

// ResolverStatus is the whole output of "resolvectl status".
type ResolverStatus struct {
	// Global is the global block.
	Global ResolverScope
	// ResolvConfMode is what systemd-resolved says about /etc/resolv.conf:
	// "stub", "static", "uplink" or "foreign". This is resolved's OBSERVATION
	// of the file, not the file itself.
	ResolvConfMode string
	// Links are the per link blocks, sorted by interface name.
	Links []ResolverScope
	// UnreadLabels are the labels this build does not record, deduplicated
	// and sorted.
	UnreadLabels []string
}

// LinkArtifactID returns the artifact id of one link. The interface name is
// the identity, not the link index resolvectl prints beside it: a recreated
// veth gets a new index without anything about the host changing, and an id
// that carried the index would report that as one link removed and one added.
func (s ResolverScope) LinkArtifactID() string {
	return ArtifactDNSLinkPrefix + "/" + s.Name
}

// dnsKnownLabels are the labels this build records. Everything else resolvectl
// prints is named in one diagnostic, so a field a newer systemd adds is
// visible instead of silently dropped.
var dnsKnownLabels = map[string]bool{
	"Protocols":          true,
	"resolv.conf mode":   true,
	"Current Scopes":     true,
	"Current DNS Server": true,
	"DNS Servers":        true,
	"DNS Domain":         true,
}

// ParseResolvectlStatus parses the output of "resolvectl status --no-pager".
// It is pure: it reads bytes and returns the status plus one diagnostic per
// line it could not read, so it is table tested from fixtures on any operating
// system.
//
// The grammar, as measured on systemd 249 and 255: blocks separated by blank
// lines, each starting with either "Global" or "Link <index> (<name>)", and
// every further line of a block a label, a colon and a value. Nothing is read
// by column, see the file comment.
func ParseResolvectlStatus(b []byte) (ResolverStatus, []trustfreeze.Diagnostic) {
	var (
		out     ResolverStatus
		diags   []trustfreeze.Diagnostic
		cur     *ResolverScope
		unread  = map[string]bool{}
		started bool
	)
	for i, raw := range privLines(b) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case line == "Global":
			cur, started = &out.Global, true
			continue
		case strings.HasPrefix(line, "Link "):
			name, ok := dnsParseLinkHeader(line)
			if !ok {
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    netDiagRecordUnparsed,
					Field:   "link",
					Message: fmt.Sprintf("line %d: %q is not the link header resolvectl prints", i+1, line),
				})
				cur, started = nil, true
				continue
			}
			out.Links = append(out.Links, ResolverScope{Name: name})
			cur, started = &out.Links[len(out.Links)-1], true
			continue
		}
		label, value, ok := dnsSplitLabel(line)
		if !ok {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   "resolver_field",
				Message: fmt.Sprintf("line %d: no label and value", i+1),
			})
			continue
		}
		if cur == nil {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   "resolver_field",
				Message: fmt.Sprintf("line %d: %q stands outside a Global or Link block", i+1, label),
			})
			continue
		}
		if !dnsKnownLabels[label] {
			unread[label] = true
			continue
		}
		dnsApplyField(&out, cur, label, value)
	}
	if !started && len(privLines(b)) > 0 {
		diags = append(diags, trustfreeze.Diagnostic{
			Code:    netDiagRecordUnparsed,
			Field:   "resolver",
			Message: "the output carries neither a Global nor a Link block",
		})
	}
	out.UnreadLabels = netSortedKeys(unread)
	sort.SliceStable(out.Links, func(i, j int) bool { return out.Links[i].Name < out.Links[j].Name })
	return out, diags
}

// dnsApplyField records one label and value on the block being read.
func dnsApplyField(out *ResolverStatus, cur *ResolverScope, label, value string) {
	switch label {
	case "resolv.conf mode":
		// resolvectl prints this in the global block only; a link block that
		// carried it would still be recorded here, because the mode is a
		// property of the host either way.
		out.ResolvConfMode = value
	case "Protocols":
		dnsApplyProtocols(cur, value)
	case "Current Scopes":
		if value == "none" {
			cur.ScopesNone = true
			return
		}
		cur.Scopes = append(cur.Scopes, strings.Fields(value)...)
	case "Current DNS Server":
		cur.CurrentDNSServer = value
	case "DNS Servers":
		cur.DNSServers = append(cur.DNSServers, strings.Fields(value)...)
	case "DNS Domain":
		for _, d := range strings.Fields(value) {
			if strings.HasPrefix(d, "~") {
				cur.RoutingOnlyDomains = append(cur.RoutingOnlyDomains, d)
				continue
			}
			cur.SearchDomains = append(cur.SearchDomains, d)
		}
	}
}

// dnsApplyProtocols reads the Protocols line: a list of "+Name" and "-Name"
// tokens plus one "DNSSEC=<mode>/<support>" token.
//
// What the sign can and cannot say: DNSOverTLS= accepts "no" and
// "opportunistic", and resolvectl prints "+DNSOverTLS" for anything that is
// not "no". The recorded "yes" therefore means "not switched off", not
// "enforced"; the setting itself lives in resolved.conf, which this probe does
// not read.
func dnsApplyProtocols(cur *ResolverScope, value string) {
	for _, tok := range strings.Fields(value) {
		if mode, support, ok := strings.Cut(strings.TrimPrefix(tok, "DNSSEC="), "/"); ok && strings.HasPrefix(tok, "DNSSEC=") {
			cur.DNSSECMode, cur.DNSSECSupport = mode, support
			continue
		}
		if strings.HasPrefix(tok, "DNSSEC=") {
			cur.DNSSECMode = strings.TrimPrefix(tok, "DNSSEC=")
			continue
		}
		state := ""
		switch {
		case strings.HasPrefix(tok, "+"):
			state = dnsYes
		case strings.HasPrefix(tok, "-"):
			state = dnsNo
		default:
			continue
		}
		switch tok[1:] {
		case "DefaultRoute":
			cur.DefaultRoute = state
		case "LLMNR":
			cur.LLMNR = state
		case "mDNS":
			cur.MDNS = state
		case "DNSOverTLS":
			cur.DNSOverTLS = state
		}
	}
}

// dnsParseLinkHeader reads the interface name out of "Link 2 (enp5s0)".
func dnsParseLinkHeader(line string) (string, bool) {
	open := strings.IndexByte(line, '(')
	if open < 0 || !strings.HasSuffix(line, ")") {
		return "", false
	}
	name := strings.TrimSpace(line[open+1 : len(line)-1])
	if name == "" {
		return "", false
	}
	return name, true
}

// dnsSplitLabel splits "Current DNS Server: 203.0.113.1" at its first colon.
// A value that carries colons of its own (an IPv6 server address) keeps them,
// because only the first colon separates.
func dnsSplitLabel(line string) (label, value string, ok bool) {
	label, value, ok = strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	label = strings.TrimSpace(label)
	if label == "" {
		return "", "", false
	}
	return label, strings.TrimSpace(value), true
}

// ResolvConf is the declared resolver configuration of /etc/resolv.conf.
type ResolvConf struct {
	Nameservers []string
	// SearchDomains are the entries of the winning "search" or "domain"
	// directive. resolv.conf(5): the two are mutually exclusive and the last
	// instance wins, which is what the parser implements.
	SearchDomains []string
	// SearchFrom names the directive the search list came from, "search" or
	// "domain", empty when neither appeared.
	SearchFrom string
	// Options are the "options" entries, in the order read.
	Options []string
	// StubResolver says a nameserver of this file is a local systemd-resolved
	// listener, so the file delegates the real decision (see dnsStubAddress).
	StubResolver bool
}

// dnsResolvConfDirectives are the directives this build records. Everything
// else is named in one diagnostic.
var dnsResolvConfDirectives = map[string]bool{
	"nameserver": true,
	"search":     true,
	"domain":     true,
	"options":    true,
}

// ParseResolvConf parses a resolv.conf. It is pure and returns one diagnostic
// per line it could not read.
//
// Comment rules of resolv.conf(5): a line whose first non-blank character is
// "#" or ";" is a comment. A directive with no value is an error of the file,
// not of the parser, and is reported as one.
func ParseResolvConf(b []byte) (ResolvConf, []trustfreeze.Diagnostic) {
	var (
		out    ResolvConf
		diags  []trustfreeze.Diagnostic
		unread = map[string]bool{}
	)
	for i, raw := range privLines(b) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		key := strings.ToLower(fields[0])
		if !dnsResolvConfDirectives[key] {
			unread[key] = true
			continue
		}
		if len(fields) < 2 {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   "resolv_conf",
				Message: fmt.Sprintf("line %d: the directive %q carries no value", i+1, key),
			})
			continue
		}
		switch key {
		case "nameserver":
			out.Nameservers = append(out.Nameservers, fields[1])
			if fields[1] == dnsStubAddress || fields[1] == dnsProxyAddress {
				out.StubResolver = true
			}
		case "search":
			out.SearchDomains, out.SearchFrom = fields[1:], "search"
		case "domain":
			// domain names exactly one domain; further words are ignored by
			// the resolver, so they are not recorded as search domains.
			out.SearchDomains, out.SearchFrom = fields[1:2], "domain"
		case "options":
			out.Options = append(out.Options, fields[1:]...)
		}
	}
	for _, k := range netSortedKeys(unread) {
		diags = append(diags, trustfreeze.Diagnostic{
			Code:    dnsDiagDirectiveUnread,
			Field:   "resolv_conf",
			Message: "the directive " + k + " is in the file and is not recorded by this build",
		})
	}
	return out, diags
}

// DNSProbe collects the resolver configuration of a Linux host.
type DNSProbe struct{}

// NewDNSProbe returns the probe.
func NewDNSProbe() *DNSProbe { return &DNSProbe{} }

// Descriptor implements probe.Probe.
func (p *DNSProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                DNSProbeID,
		Version:           DNSProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    15 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactDNSLinkPrefix, ArtifactDNSResolvConf, ArtifactDNSResolver},
	}
}

// RequiredTools implements the optional tool interface of the capture
// package: doctor resolves these names and never runs them.
func (p *DNSProbe) RequiredTools() []string { return []string{DNSTool} }

// EvidenceClaims implements probe.EvidenceClaimer.
func (p *DNSProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe. On Linux the probe is always available,
// which is deliberate and is not the pattern the tool-only probes of this
// package follow: the declared state is a file, so a host without resolvectl
// still has an answer to give, and a probe that reported itself unavailable
// there would drop /etc/resolv.conf out of the bundle over a missing binary.
// The missing tool is then recorded inside the result, with the directories it
// was looked for named.
func (p *DNSProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("resolvectl and /etc/resolv.conf are Linux sources; no resolver source for " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if host.Files == nil {
		return probe.Unavailable("no file reader")
	}
	return probe.Supported()
}

// dnsResolvectlMissingReason names the tool, where it was looked for, and what
// the bundle therefore does not know. What it must not say is that the host
// has no systemd-resolved: a resolver this build did not look in the right
// place for still answers every query the host makes.
func dnsResolvectlMissingReason(runner probe.CommandRunner) string {
	return DNSTool + " was not found " + netSearchedDirsPhrase(runner) +
		": the resolver this host really queries is not established by this capture, only what " +
		DNSResolvConfPath + " declares"
}

// Collect implements probe.Probe.
//
// The bookkeeping is the privCollector of this package (see sudo.go), because
// this probe reads a file and runs a command, which is exactly the pair that
// collector exists for.
func (p *DNSProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := newPrivCollector(ctx, cc)
	res := privBaseResult(DNSProbeID, DNSProbeVersion, cc, start)

	arts, states := p.observed(c)
	declared, declaredState := p.declared(c)
	if declared != nil {
		arts = append(arts, *declared)
	}
	states = append(states, declaredState)
	states = append(states, c.extraStates()...)

	res.Status, res.Reason, res.Error = privStatus(states, "the resolver configuration of this host")
	return c.finish(res, arts, start)
}

// observed runs resolvectl and builds the observed artifacts. A host where
// resolvectl is missing, refused or unreadable yields no observed artifact at
// all: a resolver artifact with empty fields would read as a host that
// resolves nothing, and the honest statement is that the observed state is not
// in this bundle.
func (p *DNSProbe) observed(c *privCollector) ([]trustfreeze.Artifact, []privState) {
	if _, err := c.cc.Runner.LookPath(DNSTool); err != nil {
		st := privCommandState(err)
		if st == privUnavailable {
			reason := dnsResolvectlMissingReason(c.cc.Runner)
			c.warn(probe.DiagFieldUnavailable, "resolver", reason)
			c.warn(dnsDiagResolverUnknown, "resolver", reason)
			return nil, []privState{privUnavailable}
		}
		c.warn(privStateCode(st), "resolver", DNSTool+": "+err.Error())
		return nil, []privState{st}
	}
	version := c.recordVersion(DNSTool, []string{"--version"}, privStdout)

	r := c.run(DNSTool, "status", "--no-pager")
	switch {
	case r.State != privOK:
		c.warn(privStateCode(r.State), "resolver", DNSTool+" status: "+r.Detail)
		c.warn(dnsDiagResolverUnknown, "resolver", "the observed resolver state is not in this bundle: "+r.Detail)
		return nil, []privState{r.State}
	case r.ExitCode != 0:
		// resolvectl exits non-zero when systemd-resolved does not answer its
		// bus call, which is the shape of a host where the service is
		// installed but not running. That is a fact about the host, and it is
		// recorded as one: no observed artifact, the declared file still read.
		detail := fmt.Sprintf("exit status %d", r.ExitCode)
		if first := privFirstLine(r.Stderr); first != "" {
			detail += ": " + first
		}
		st := privFailed
		if privLooksDenied(detail) {
			st = privPermissionDenied
		}
		c.warn(privStateCode(st), "resolver", DNSTool+" status: "+detail)
		c.warn(dnsDiagResolverUnknown, "resolver", "the observed resolver state is not in this bundle: "+detail)
		c.addEvidence("resolvectl-status.stderr.txt", "stderr:"+DNSTool, r.StderrData, r.StderrTruncated)
		return nil, []privState{st}
	}
	c.addEvidence("resolvectl-status.txt", "stdout:"+DNSTool, r.StdoutData, r.StdoutTruncated)
	c.addSource("command:" + DNSTool + " status --no-pager")

	status, diags := ParseResolvectlStatus(r.Stdout)
	states := []privState{privOK}
	for _, d := range diags {
		c.warn(d.Code, "resolver", d.Message)
		states = append(states, privPartial)
	}
	if len(status.UnreadLabels) > 0 {
		c.warn(dnsDiagFieldUnread, "resolver",
			"resolvectl printed fields this build does not record: "+strings.Join(status.UnreadLabels, ", "))
	}
	sources := c.sources

	links := status.Links
	if len(links) > dnsMaxLinks {
		c.warn(netDiagVolumeCapped, "link",
			fmt.Sprintf("%d links; only the first %d are recorded as artifacts", len(links), dnsMaxLinks))
		links = links[:dnsMaxLinks]
		states = append(states, privPartial)
	}
	arts := make([]trustfreeze.Artifact, 0, len(links)+1)
	arts = append(arts, c.artifact(ArtifactDNSResolver, artifactTypeDNSResolver, "device",
		trustfreeze.StateObserved, dnsResolverAttributes(status, links, len(status.Links)), "command",
		trustfreeze.ConfidenceProven, sources, version, trustfreeze.SensitivityInternal))
	for _, l := range links {
		arts = append(arts, c.artifact(l.LinkArtifactID(), artifactTypeDNSLink, "device",
			trustfreeze.StateObserved, dnsLinkAttributes(l), "command",
			trustfreeze.ConfidenceProven, sources, version, trustfreeze.SensitivityInternal))
	}
	return arts, states
}

// declared reads /etc/resolv.conf and builds the declared artifact. The file
// is the declared state whatever resolvectl said, and it never becomes
// observed (playbook L3).
func (p *DNSProbe) declared(c *privCollector) (*trustfreeze.Artifact, privState) {
	raw, st, detail := c.readFile(DNSResolvConfPath)
	if st != privOK {
		c.warn(privStateCode(st), "resolv_conf", detail)
		// The file is named in an artifact even when it was not read, so that
		// a bundle says which path was asked for and why the answer is
		// missing, instead of leaving the reader to guess that it was never
		// tried.
		a := c.artifact(ArtifactDNSResolvConf, artifactTypeDNSResolvConf, "device",
			trustfreeze.StateUnknown, map[string]string{
				"path":               DNSResolvConfPath,
				"read":               privBool(false),
				"read_failure_class": privStateCode(st),
			}, "file", trustfreeze.ConfidenceUnknown, nil, "", trustfreeze.SensitivityInternal)
		return &a, st
	}
	if data, ok := c.redactFile(DNSResolvConfPath, raw); ok {
		c.addEvidence(privEvidenceName(DNSResolvConfPath), "file:"+DNSResolvConfPath, data, false)
	}
	conf, diags := ParseResolvConf(raw)
	state := privOK
	for _, d := range diags {
		c.warn(d.Code, "resolv_conf", d.Message)
		if d.Code == netDiagRecordUnparsed {
			state = privPartial
		}
	}
	a := c.artifact(ArtifactDNSResolvConf, artifactTypeDNSResolvConf, "device",
		trustfreeze.StateDeclared, dnsResolvConfAttributes(conf), "file",
		trustfreeze.ConfidenceProven, []string{"file:" + DNSResolvConfPath}, "",
		trustfreeze.SensitivityInternal)
	return &a, state
}

// dnsResolverAttributes builds the global observed artifact. printed is how
// many link blocks resolvectl printed, which is the count the artifact states
// even where the volume cap kept some of them out of the artifact list: a count
// over a capped list is a claim about the host that nobody measured.
func dnsResolverAttributes(s ResolverStatus, links []ResolverScope, printed int) map[string]string {
	attrs := map[string]string{
		"tool":                 DNSTool,
		"link_count":           strconv.Itoa(printed),
		"link_artifact_count":  strconv.Itoa(len(links)),
		"resolving_link_count": strconv.Itoa(dnsResolvingLinks(links)),
	}
	dnsPutIfSet(attrs, map[string]string{
		"resolv_conf_mode": s.ResolvConfMode,
		"dnssec_mode":      s.Global.DNSSECMode,
		"dnssec_support":   s.Global.DNSSECSupport,
		"dns_over_tls":     s.Global.DNSOverTLS,
		"llmnr":            s.Global.LLMNR,
		"mdns":             s.Global.MDNS,
	})
	dnsPutList(attrs, "dns_servers", s.Global.DNSServers)
	dnsPutList(attrs, "search_domains", s.Global.SearchDomains)
	dnsPutList(attrs, "routing_only_domains", s.Global.RoutingOnlyDomains)
	return attrs
}

// dnsResolvingLinks counts the links that resolve anything at all, which is
// the number a reader of a container host needs: 26 of 27 links printing
// "Current Scopes: none" is not 27 resolvers.
func dnsResolvingLinks(links []ResolverScope) int {
	n := 0
	for _, l := range links {
		if len(l.Scopes) > 0 {
			n++
		}
	}
	return n
}

// dnsLinkAttributes builds one observed link artifact.
func dnsLinkAttributes(l ResolverScope) map[string]string {
	attrs := map[string]string{
		"interface":    l.Name,
		"resolves":     privBool(len(l.Scopes) > 0),
		"scopes_none":  privBool(l.ScopesNone),
		"server_count": strconv.Itoa(len(l.DNSServers)),
	}
	dnsPutIfSet(attrs, map[string]string{
		"default_route":      l.DefaultRoute,
		"llmnr":              l.LLMNR,
		"mdns":               l.MDNS,
		"dns_over_tls":       l.DNSOverTLS,
		"dnssec_mode":        l.DNSSECMode,
		"dnssec_support":     l.DNSSECSupport,
		"current_dns_server": l.CurrentDNSServer,
	})
	dnsPutList(attrs, "scopes", l.Scopes)
	dnsPutList(attrs, "dns_servers", l.DNSServers)
	dnsPutList(attrs, "search_domains", l.SearchDomains)
	dnsPutList(attrs, "routing_only_domains", l.RoutingOnlyDomains)
	return attrs
}

// dnsResolvConfAttributes builds the declared artifact.
func dnsResolvConfAttributes(c ResolvConf) map[string]string {
	attrs := map[string]string{
		"path":                  DNSResolvConfPath,
		"read":                  privBool(true),
		"nameserver_count":      strconv.Itoa(len(c.Nameservers)),
		"systemd_resolved_stub": privBool(c.StubResolver),
	}
	dnsPutIfSet(attrs, map[string]string{"search_from": c.SearchFrom})
	dnsPutList(attrs, "nameservers", c.Nameservers)
	dnsPutList(attrs, "search_domains", c.SearchDomains)
	dnsPutList(attrs, "options", c.Options)
	return attrs
}

// dnsPutIfSet copies the non-empty entries of in into attrs.
func dnsPutIfSet(attrs, in map[string]string) {
	for _, k := range netSortedKeys(in) {
		if in[k] != "" {
			attrs[k] = in[k]
		}
	}
}

// dnsPutList records a list as one comma separated value, capped, with the cut
// stated beside it so a reader never takes a cut list for the whole one.
func dnsPutList(attrs map[string]string, key string, values []string) {
	if len(values) == 0 {
		return
	}
	v, cut := privCapList(values, dnsMaxValueBytes)
	attrs[key] = v
	if cut {
		attrs[key+"_truncated"] = privBool(true)
	}
}
