package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// linux.firewall reports the packet filter state of the host (SPEC-0471
// TF06-R3). The authoritative source is "nft --json list ruleset"; "ufw
// status" is the fallback for a host that only has the Ubuntu front end.
//
// Both tools refuse an unprivileged caller: nft answers "Operation not
// permitted (you must be root)" and ufw answers "ERROR: You need to be root
// to run this script", each with exit code 1 and nothing on stdout. The
// honest result of an unprivileged capture on such a host is therefore
// permission_denied with the installed backends recorded, never unavailable
// (the tools are there) and never an empty ruleset (an empty ruleset means
// everything passes, which is the opposite claim). A host with neither
// backend has no firewall to describe: not_applicable with a reason.
//
// What is persisted from a ruleset that could be read: the tables, the
// chains with their type, hook, priority and policy, and the number of rules
// per chain. The rules themselves are not persisted verbatim unless they are
// small and carry no address literal, because a rule set names source and
// destination addresses, which are personal data under the data protection
// rules this collector has to keep.
const (
	// FirewallProbeID is the probe id of the firewall probe.
	FirewallProbeID = "linux.firewall"
	// FirewallProbeVersion changes whenever the output of the probe can
	// change.
	FirewallProbeVersion = "1"
	// FirewallToolNft and FirewallToolUfw are the backends, in the order
	// the probe tries them.
	FirewallToolNft = "nft"
	FirewallToolUfw = "ufw"
)

// Artifact ids of the firewall probe.
const (
	ArtifactFirewall       = "security/firewall"
	artifactFirewallNft    = ArtifactFirewall + "/nft"
	artifactFirewallUfw    = ArtifactFirewall + "/ufw"
	artifactTypeFirewall   = "firewall"
	artifactTypeFwTable    = "firewall-table"
	artifactTypeFwChain    = "firewall-chain"
	artifactTypeFwFrontend = "firewall-frontend"
)

// Observation states of the firewall probe, recorded as an attribute so that
// a bundle says why it knows or does not know the firewall state.
const (
	observationObserved         = "observed"
	observationPermissionDenied = "permission_denied"
	observationFailed           = "failed"
	observationNotApplicable    = "not_applicable"
)

// nftRulesetEvidenceMaxBytes bounds the ruleset output that may be kept as
// raw evidence. Anything larger is summarized only.
const nftRulesetEvidenceMaxBytes = 4096

// netAddressLiteral matches an IPv4 dotted quad or an IPv6 shaped token. It
// is deliberately eager: output that only looks like an address is withheld
// too, because the cost of withholding is a diagnostic and the cost of a
// false negative is personal data in a bundle.
var netAddressLiteral = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:]*`)

// netContainsAddressLiteral reports whether b carries something shaped like
// an IP address.
func netContainsAddressLiteral(b []byte) bool { return netAddressLiteral.Match(b) }

// NftChain is one chain of an nftables ruleset.
type NftChain struct {
	Family   string
	Table    string
	Name     string
	Type     string
	Hook     string
	Priority string
	Policy   string
	Rules    int
}

// NftTable is one table of an nftables ruleset.
type NftTable struct {
	Family string
	Name   string
	Chains int
	Rules  int
}

// NftRuleset is the summary of an nftables ruleset: what the chains are,
// which policy they enforce and how many rules they hold. The rules
// themselves are not part of it.
type NftRuleset struct {
	Version string
	Tables  []NftTable
	Chains  []NftChain
	Rules   int
}

// ErrNftRuleset is returned by ParseNftJSONRuleset for output that is not an
// nftables JSON document.
var ErrNftRuleset = errors.New("linux: not an nftables json ruleset")

// nftDocument is the part of the libnftables JSON schema this probe reads.
// Unknown members are ignored on purpose: the schema grows, and a new
// expression type must not make the probe fail.
type nftDocument struct {
	Nftables []struct {
		Metainfo *struct {
			Version string `json:"version"`
		} `json:"metainfo"`
		Table *struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		} `json:"table"`
		Chain *struct {
			Family string          `json:"family"`
			Table  string          `json:"table"`
			Name   string          `json:"name"`
			Type   string          `json:"type"`
			Hook   string          `json:"hook"`
			Prio   json.RawMessage `json:"prio"`
			Policy string          `json:"policy"`
		} `json:"chain"`
		Rule *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Chain  string `json:"chain"`
		} `json:"rule"`
	} `json:"nftables"`
}

// ParseNftJSONRuleset reads the output of "nft --json list ruleset". It is
// pure and returns an error for anything that is not such a document, so a
// caller that forgot to check the exit code cannot mistake a refusal on
// stderr for an empty ruleset.
func ParseNftJSONRuleset(b []byte) (NftRuleset, error) {
	var doc nftDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		return NftRuleset{}, fmt.Errorf("%w: %w", ErrNftRuleset, err)
	}
	if doc.Nftables == nil {
		return NftRuleset{}, fmt.Errorf("%w: no nftables member", ErrNftRuleset)
	}
	var out NftRuleset
	tables := map[string]*NftTable{}
	chains := map[string]*NftChain{}
	tableKey := func(family, name string) string { return family + "\x00" + name }
	chainKey := func(family, table, name string) string { return family + "\x00" + table + "\x00" + name }
	for _, item := range doc.Nftables {
		switch {
		case item.Metainfo != nil:
			out.Version = item.Metainfo.Version
		case item.Table != nil:
			k := tableKey(item.Table.Family, item.Table.Name)
			if _, ok := tables[k]; !ok {
				tables[k] = &NftTable{Family: item.Table.Family, Name: item.Table.Name}
			}
		case item.Chain != nil:
			k := chainKey(item.Chain.Family, item.Chain.Table, item.Chain.Name)
			if _, ok := chains[k]; !ok {
				chains[k] = &NftChain{
					Family:   item.Chain.Family,
					Table:    item.Chain.Table,
					Name:     item.Chain.Name,
					Type:     item.Chain.Type,
					Hook:     item.Chain.Hook,
					Priority: nftPriority(item.Chain.Prio),
					Policy:   item.Chain.Policy,
				}
			}
			tk := tableKey(item.Chain.Family, item.Chain.Table)
			if _, ok := tables[tk]; !ok {
				tables[tk] = &NftTable{Family: item.Chain.Family, Name: item.Chain.Table}
			}
			tables[tk].Chains++
		case item.Rule != nil:
			out.Rules++
			ck := chainKey(item.Rule.Family, item.Rule.Table, item.Rule.Chain)
			if _, ok := chains[ck]; !ok {
				chains[ck] = &NftChain{Family: item.Rule.Family, Table: item.Rule.Table, Name: item.Rule.Chain}
			}
			chains[ck].Rules++
			tk := tableKey(item.Rule.Family, item.Rule.Table)
			if _, ok := tables[tk]; !ok {
				tables[tk] = &NftTable{Family: item.Rule.Family, Name: item.Rule.Table}
			}
			tables[tk].Rules++
		}
	}
	for _, k := range netSortedKeys(tables) {
		out.Tables = append(out.Tables, *tables[k])
	}
	for _, k := range netSortedKeys(chains) {
		out.Chains = append(out.Chains, *chains[k])
	}
	sort.SliceStable(out.Tables, func(i, j int) bool {
		if out.Tables[i].Family != out.Tables[j].Family {
			return out.Tables[i].Family < out.Tables[j].Family
		}
		return out.Tables[i].Name < out.Tables[j].Name
	})
	sort.SliceStable(out.Chains, func(i, j int) bool {
		a, b := out.Chains[i], out.Chains[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		return a.Name < b.Name
	})
	return out, nil
}

// nftPriority renders the chain priority, which nft prints as a number or as
// a name such as "filter". An unknown shape yields an empty string, never a
// guess.
func nftPriority(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	switch {
	case s == "" || s == "null":
		return ""
	case strings.HasPrefix(s, `"`):
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return ""
		}
		return v
	case strings.HasPrefix(s, "{"), strings.HasPrefix(s, "["):
		return ""
	}
	return s
}

// UfwStatus is what "ufw status" reports: the front end state and how many
// rule lines its table holds.
type UfwStatus struct {
	// Status is the value of the "Status:" line, lower case, for example
	// "active" or "inactive".
	Status string
	Rules  int
}

// ErrUfwStatus is returned by ParseUfwStatus for output without a status
// line.
var ErrUfwStatus = errors.New("linux: not a ufw status output")

// ParseUfwStatus reads the output of "ufw status". It is pure. The trial
// host refused the call, so this parser was measured against the refusal
// path only; the shape of a successful run is ufw's documented one, a
// "Status:" line followed by an optional table whose header is separated by
// a line of dashes.
func ParseUfwStatus(b []byte) (UfwStatus, error) {
	var (
		out       UfwStatus
		hasStatus bool
		inTable   bool
	)
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "Status:"):
			out.Status = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:")))
			hasStatus = true
		case isDashRow(trimmed):
			inTable = true
		case inTable:
			out.Rules++
		}
	}
	if !hasStatus {
		return UfwStatus{}, ErrUfwStatus
	}
	return out, nil
}

// isDashRow reports whether every field of the line consists of dashes,
// which is the separator ufw prints under its table header.
func isDashRow(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if strings.Trim(f, "-") != "" {
			return false
		}
	}
	return true
}

// FirewallProbe collects the packet filter state of a Linux host.
type FirewallProbe struct{}

// NewFirewallProbe returns the probe.
func NewFirewallProbe() *FirewallProbe { return &FirewallProbe{} }

// Descriptor implements probe.Probe.
func (p *FirewallProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                FirewallProbeID,
		Version:           FirewallProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeElevated,
		DefaultTimeout:    20 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactFirewall},
	}
}

// RequiredTools implements the optional tool interface of the capture
// package.
func (p *FirewallProbe) RequiredTools() []string { return []string{FirewallToolNft, FirewallToolUfw} }

// EvidenceClaims implements probe.EvidenceClaimer.
func (p *FirewallProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe. A host with neither backend has no
// firewall this probe can describe.
func (p *FirewallProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("nft and ufw are Linux tools; no firewall source for " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if len(netPresentTools(host, FirewallToolNft, FirewallToolUfw)) == 0 {
		return probe.NotApplicable("no firewall backend on this host: neither nft nor ufw is installed")
	}
	return probe.Supported()
}

// netPresentTools returns the executables of names that resolve, in the
// given order. A tool that exists but is not executable counts as present:
// its refusal is a privilege statement, not an absence.
func netPresentTools(host probe.HostContext, names ...string) []string {
	var out []string
	for _, n := range names {
		if host.Runner == nil {
			return nil
		}
		if _, err := host.Runner.LookPath(n); err != nil {
			if probe.ErrorClass(err) == probe.ClassPermissionDenied {
				out = append(out, n)
			}
			continue
		}
		out = append(out, n)
	}
	return out
}

// Collect implements probe.Probe.
func (p *FirewallProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	s := newNetProbeState(ctx, cc)
	res := s.base(FirewallProbeID, FirewallProbeVersion, start)
	present := netPresentTools(cc.HostContext, FirewallToolNft, FirewallToolUfw)
	observed := trustfreeze.FormatTime(start)

	if len(present) == 0 {
		res.Status = trustfreeze.StatusNotApplicable
		res.Reason = "no firewall backend on this host: neither nft nor ufw is installed"
		return s.finish(res, []trustfreeze.Artifact{{
			ID: ArtifactFirewall, Type: artifactTypeFirewall, Scope: "device", Source: FirewallProbeID,
			State: trustfreeze.StateUnknown,
			Attributes: map[string]string{
				"backends_present": "",
				"backend_observed": "",
				"observation":      observationNotApplicable,
			},
			Provenance: trustfreeze.Provenance{
				Method: "command", Confidence: trustfreeze.ConfidenceProven,
				Sources: []string{"lookpath:nft", "lookpath:ufw"}, ObservedAt: observed,
			},
			Sensitivity: trustfreeze.SensitivityPublic,
		}}, start)
	}

	var (
		arts       []trustfreeze.Artifact
		backend    string
		version    string
		nftVersion string
		ufwVersion string
		refusals   []string
		failures   []string
		partial    bool
	)
	has := func(name string) bool {
		for _, n := range present {
			if n == name {
				return true
			}
		}
		return false
	}

	if has(FirewallToolNft) {
		nftVersion = s.toolVersion(FirewallToolNft, []string{"--version"}, "nft-version.stdout")
		version = nftVersion
		cmd := s.run(FirewallToolNft, []string{"--json", "list", "ruleset"})
		switch cmd.Status {
		case trustfreeze.StatusCaptured:
			// The exit code was checked first: a refusal never reaches the
			// decoder, because the refusal is on stderr and stdout is empty.
			if r := s.truncationCheck(cmd, "nft_ruleset", "the rule set is incomplete and was not parsed"); r != "" {
				partial = true
				failures = append(failures, "nft --json list ruleset: "+r)
				break
			}
			rs, err := ParseNftJSONRuleset(cmd.Res.Stdout.Bytes())
			if err != nil {
				partial = true
				s.warn(netDiagRecordUnparsed, "nft_ruleset", "nft --json list ruleset: "+err.Error())
				break
			}
			backend = FirewallToolNft
			if rs.Version != "" {
				// The ruleset states the version of the library that
				// produced it, which is the version the parser is valid for.
				nftVersion = FirewallToolNft + " " + rs.Version
			}
			version = nftVersion
			s.keepRulesetEvidence("nft-list-ruleset.json", "stdout:nft", cmd)
			arts = append(arts, nftArtifacts(rs, s.sourceList(), version, observed)...)
		case trustfreeze.StatusPermissionDenied:
			refusals = append(refusals, "nft --json list ruleset: "+cmd.Detail)
			s.warn(probe.DiagFieldPermissionDenied, "nft_ruleset", "nft --json list ruleset: "+cmd.Detail)
			s.evidenceIfAny("nft-list-ruleset.stderr", "stderr:nft", cmd.Res.Stderr, cmd.Res.StderrTruncated)
		default:
			failures = append(failures, "nft --json list ruleset: "+cmd.Detail)
			s.warn(netDiagCode(cmd.Status), "nft_ruleset", "nft --json list ruleset: "+cmd.Detail)
			s.evidenceIfAny("nft-list-ruleset.stderr", "stderr:nft", cmd.Res.Stderr, cmd.Res.StderrTruncated)
		}
	}

	if backend == "" && has(FirewallToolUfw) {
		ufwVersion = s.toolVersion(FirewallToolUfw, []string{"--version"}, "ufw-version.stdout")
		if version == "" {
			version = ufwVersion
		}
		cmd := s.run(FirewallToolUfw, []string{"status"})
		switch cmd.Status {
		case trustfreeze.StatusCaptured:
			if r := s.truncationCheck(cmd, "ufw_status", "the rules beyond the cut are not in this bundle, and rule_count counts what was read"); r != "" {
				partial = true
				failures = append(failures, "ufw status: "+r)
			}
			st, err := ParseUfwStatus(cmd.Res.Stdout.Bytes())
			if err != nil {
				partial = true
				s.warn(netDiagRecordUnparsed, "ufw_status", "ufw status: "+err.Error())
				break
			}
			backend = FirewallToolUfw
			version = ufwVersion
			s.keepRulesetEvidence("ufw-status.stdout", "stdout:ufw", cmd)
			arts = append(arts, trustfreeze.Artifact{
				ID: artifactFirewallUfw, Type: artifactTypeFwFrontend, Scope: "device", Source: FirewallProbeID,
				State: trustfreeze.StateObserved,
				Attributes: map[string]string{
					"backend":    FirewallToolUfw,
					"status":     st.Status,
					"rule_count": strconv.Itoa(st.Rules),
				},
				Provenance: trustfreeze.Provenance{
					Method: "command", Confidence: trustfreeze.ConfidenceProven,
					Sources: s.sourceList(), ObservedAt: observed, ToolVersion: version,
				},
				Sensitivity: trustfreeze.SensitivityInternal,
			})
		case trustfreeze.StatusPermissionDenied:
			refusals = append(refusals, "ufw status: "+cmd.Detail)
			s.warn(probe.DiagFieldPermissionDenied, "ufw_status", "ufw status: "+cmd.Detail)
			s.evidenceIfAny("ufw-status.stderr", "stderr:ufw", cmd.Res.Stderr, cmd.Res.StderrTruncated)
		default:
			failures = append(failures, "ufw status: "+cmd.Detail)
			s.warn(netDiagCode(cmd.Status), "ufw_status", "ufw status: "+cmd.Detail)
			s.evidenceIfAny("ufw-status.stderr", "stderr:ufw", cmd.Res.Stderr, cmd.Res.StderrTruncated)
		}
	}

	observation := observationObserved
	switch {
	case backend != "":
		res.Status = trustfreeze.StatusCaptured
		if partial || len(refusals) > 0 || len(failures) > 0 {
			res.Status = trustfreeze.StatusPartial
			res.Reason = strings.Join(append(append([]string{}, refusals...), failures...), "; ")
		}
	case len(refusals) > 0:
		observation = observationPermissionDenied
		res.Status = trustfreeze.StatusPermissionDenied
		res.Reason = strings.Join(refusals, "; ")
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassPermissionDenied, Message: res.Reason}
	default:
		observation = observationFailed
		res.Status = trustfreeze.StatusFailed
		res.Reason = strings.Join(failures, "; ")
		if res.Reason == "" {
			res.Reason = "no firewall backend answered"
		}
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTerminated, Message: res.Reason}
	}
	if partial && res.Status == trustfreeze.StatusCaptured {
		res.Status = trustfreeze.StatusPartial
	}

	state := trustfreeze.StateObserved
	if backend == "" {
		state = trustfreeze.StateUnknown
	}
	sources := s.sourceList()
	for _, n := range present {
		sources = append(sources, "lookpath:"+n)
	}
	sort.Strings(sources)
	arts = append(arts, trustfreeze.Artifact{
		ID: ArtifactFirewall, Type: artifactTypeFirewall, Scope: "device", Source: FirewallProbeID,
		State: state,
		Attributes: map[string]string{
			"backends_present": strings.Join(present, ","),
			"backend_observed": backend,
			"observation":      observation,
		},
		Provenance: trustfreeze.Provenance{
			Method: "command", Confidence: trustfreeze.ConfidenceProven,
			Sources: sources, ObservedAt: observed, ToolVersion: version,
		},
		Sensitivity: trustfreeze.SensitivityPublic,
	})
	return s.finish(res, arts, start)
}

// keepRulesetEvidence persists a ruleset only when it is small and carries
// no address literal; otherwise it records why the bytes were withheld. The
// derived artifacts are persisted either way.
func (s *netProbeState) keepRulesetEvidence(name, source string, cmd netCmd) {
	b := cmd.Res.Stdout.Bytes()
	switch {
	case len(b) == 0:
		return
	case len(b) > nftRulesetEvidenceMaxBytes:
		s.warn(netDiagEvidenceWithheld, "", fmt.Sprintf("%s: %d bytes of ruleset output were not persisted; the chains, policies and rule counts are in the artifacts", name, len(b)))
	case netContainsAddressLiteral(b):
		s.warn(netDiagEvidenceWithheld, "", name+": the ruleset output carries address literals and was not persisted; the chains, policies and rule counts are in the artifacts")
	default:
		s.evidence(name, source, cmd.Res.Stdout, cmd.Res.StdoutTruncated)
	}
}

// nftArtifacts turns a ruleset summary into one artifact per table and per
// chain plus nothing else: the rules themselves stay out.
func nftArtifacts(rs NftRuleset, sources []string, version, observed string) []trustfreeze.Artifact {
	prov := trustfreeze.Provenance{
		Method: "command", Confidence: trustfreeze.ConfidenceProven,
		Sources: sources, ObservedAt: observed, ToolVersion: version,
	}
	out := make([]trustfreeze.Artifact, 0, len(rs.Tables)+len(rs.Chains))
	for _, t := range rs.Tables {
		out = append(out, trustfreeze.Artifact{
			ID:    artifactFirewallNft + "/" + t.Family + "/" + t.Name,
			Type:  artifactTypeFwTable,
			Scope: "device", Source: FirewallProbeID,
			State: trustfreeze.StateObserved,
			Attributes: map[string]string{
				"backend":     FirewallToolNft,
				"family":      t.Family,
				"table":       t.Name,
				"chain_count": strconv.Itoa(t.Chains),
				"rule_count":  strconv.Itoa(t.Rules),
			},
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	for _, c := range rs.Chains {
		attrs := map[string]string{
			"backend":    FirewallToolNft,
			"family":     c.Family,
			"table":      c.Table,
			"chain":      c.Name,
			"rule_count": strconv.Itoa(c.Rules),
		}
		for k, v := range map[string]string{"type": c.Type, "hook": c.Hook, "priority": c.Priority, "policy": c.Policy} {
			if v != "" {
				attrs[k] = v
			}
		}
		out = append(out, trustfreeze.Artifact{
			ID:    artifactFirewallNft + "/" + c.Family + "/" + c.Table + "/" + c.Name,
			Type:  artifactTypeFwChain,
			Scope: "device", Source: FirewallProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	return out
}
