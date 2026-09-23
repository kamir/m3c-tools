package linux

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// Constructed inputs of this file, and why they are constructed: both
// firewall backends of the trial host refuse an unprivileged caller, so the
// fixture set carries the two refusals and no ruleset at all
// (testdata/README.md, "What this host could not show"). The refusal paths
// below run against those fixtures byte for byte. The two success paths run
// against documents written from the documented output of the tools, which
// is stated here so that nobody reads them as measured host output.

// nftRulesetJSON is a constructed libnftables document: one inet table with
// two base chains and two rules, in the member order nft emits.
const nftRulesetJSON = `{"nftables": [
  {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
  {"table": {"family": "inet", "name": "filter", "handle": 1}},
  {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
  {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": "filter", "policy": "accept"}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "expr": [{"accept": null}]}}
]}`

// ufwStatusText is a constructed "ufw status" answer in the documented
// shape: a status line, the table header, the dashed separator and two rule
// rows.
const ufwStatusText = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n22/tcp (v6)                ALLOW       Anywhere (v6)\n"

// netFirewallRunner scripts both backends with the refusal fixtures of the
// trial host.
func netFirewallRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().
		AddTool(FirewallToolNft, "/usr/sbin/nft").
		AddTool(FirewallToolUfw, "/usr/sbin/ufw").
		Script(FirewallToolNft, []string{"--version"}, probe.FakeResponse{Stdout: netFixture(t, "firewall/nft-version.txt")}).
		Script(FirewallToolNft, []string{"--json", "list", "ruleset"}, probe.FakeResponse{
			Stderr:   netFixture(t, "firewall/nft-json-list-ruleset.stderr.txt"),
			ExitCode: 1,
		}).
		Script(FirewallToolUfw, []string{"--version"}, probe.FakeResponse{Stdout: netFixture(t, "firewall/ufw-version.txt")}).
		Script(FirewallToolUfw, []string{"status"}, probe.FakeResponse{
			Stderr:   netFixture(t, "firewall/ufw-status.stderr.txt"),
			ExitCode: 1,
		})
}

// TF06-R2: both tools are installed and both refuse without root. The
// honest status is permission_denied with the backends recorded, never
// unavailable and never an empty ruleset.
func TestFirewallProbeRefusedByBothBackends(t *testing.T) {
	cc, ev := netTestCollect(FirewallProbeID, netFirewallRunner(t))
	res := NewFirewallProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q, want permission_denied (reason %q)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "Operation not permitted (you must be root)") {
		t.Errorf("reason %q does not carry the refusal nft printed", res.Reason)
	}
	if !strings.Contains(res.Reason, "You need to be root to run this script") {
		t.Errorf("reason %q does not carry the refusal ufw printed", res.Reason)
	}
	if res.Error == nil || res.Error.Class != probe.ClassPermissionDenied {
		t.Errorf("error %+v, want the permission_denied class", res.Error)
	}
	fw := netArtifact(t, res, ArtifactFirewall)
	for k, want := range map[string]string{
		"backends_present": "nft,ufw",
		"backend_observed": "",
		"observation":      observationPermissionDenied,
	} {
		if fw.Attributes[k] != want {
			t.Errorf("%s = %q, want %q", k, fw.Attributes[k], want)
		}
	}
	if fw.State != trustfreeze.StateUnknown {
		t.Errorf("state %q, want unknown: the firewall state of this host was not observed", fw.State)
	}
	if len(res.NormalizedState) != 1 {
		t.Errorf("a refused firewall probe must not invent chains: %v", netArtifactIDs(res))
	}
	names := netEvidenceNames(ev)
	for _, want := range []string{"nft-list-ruleset.stderr", "nft-version.stdout", "ufw-status.stderr", "ufw-version.stdout"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("evidence %q missing from %v", want, names)
		}
	}
}

// Neither backend in the searched directories is unavailable with a reason
// that names those directories, and the artifact says so. Until 2026-09-23
// this was not_applicable with the words "no firewall backend on this host",
// which is a claim about the host: nft and ufw are two front ends among
// several, and a ruleset loaded at boot filters without either of them being
// installed. Same defect class as the container runtime found at a snap
// path, and the same fix.
func TestFirewallProbeWithoutAnyBackend(t *testing.T) {
	runner := probe.NewFakeRunner().WithSearchDirs(netBastionSearchDirs...)
	p := NewFirewallProbe()
	sup := p.Support(context.Background(), netTestHost(runner))
	if sup.Available || sup.Status != trustfreeze.StatusUnavailable || sup.Reason == "" {
		t.Fatalf("support %+v, want unavailable with a reason", sup)
	}
	cc, _ := netTestCollect(FirewallProbeID, runner)
	res := p.Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusUnavailable || res.Reason == "" {
		t.Fatalf("status %q reason %q, want unavailable with a reason", res.Status, res.Reason)
	}
	if res.Error == nil || res.Error.Class != probe.ClassToolMissing {
		t.Errorf("error %+v, want class %q", res.Error, probe.ClassToolMissing)
	}
	if strings.Contains(res.Reason, "no firewall backend on this host") {
		t.Errorf("reason %q still claims the host has no firewall", res.Reason)
	}
	for _, dir := range netBastionSearchDirs {
		if !strings.Contains(res.Reason, dir) {
			t.Errorf("reason %q does not name the searched directory %s", res.Reason, dir)
		}
	}
	if !netHasWarning(res, probe.DiagFieldUnavailable, "backend") {
		t.Errorf("no field_unavailable diagnostic: %+v", res.Warnings)
	}
	fw := netArtifact(t, res, ArtifactFirewall)
	if fw.Attributes["observation"] != observationUnavailable || fw.Attributes["backends_present"] != "" {
		t.Errorf("attributes %v", fw.Attributes)
	}
}

// The refusal arrives on stderr with an empty stdout, so a parser that
// forgot the exit code would decode nothing. ParseNftJSONRuleset refuses
// both the empty document and the refusal text, which is what keeps "no
// output" from turning into "no rules".
func TestParseNftJSONRulesetRefusesNonDocuments(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte(""),
		netFixture(t, "firewall/nft-json-list-ruleset.stderr.txt"),
		[]byte(`{"other": []}`),
	} {
		if _, err := ParseNftJSONRuleset(in); !errors.Is(err, ErrNftRuleset) {
			t.Errorf("ParseNftJSONRuleset(%q) error = %v, want ErrNftRuleset", string(in), err)
		}
	}
}

func TestParseNftJSONRuleset(t *testing.T) {
	rs, err := ParseNftJSONRuleset([]byte(nftRulesetJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rs.Version != "1.0.9" {
		t.Errorf("version %q", rs.Version)
	}
	if rs.Rules != 2 {
		t.Errorf("rule count %d, want 2", rs.Rules)
	}
	if len(rs.Tables) != 1 || rs.Tables[0].Family != "inet" || rs.Tables[0].Name != "filter" ||
		rs.Tables[0].Chains != 2 || rs.Tables[0].Rules != 2 {
		t.Errorf("tables %+v", rs.Tables)
	}
	if len(rs.Chains) != 2 {
		t.Fatalf("chains %+v", rs.Chains)
	}
	// Sorted by family, table and name: forward before input.
	if rs.Chains[0].Name != "forward" || rs.Chains[0].Policy != "accept" || rs.Chains[0].Priority != "filter" || rs.Chains[0].Rules != 0 {
		t.Errorf("chain[0] %+v", rs.Chains[0])
	}
	if rs.Chains[1].Name != "input" || rs.Chains[1].Policy != "drop" || rs.Chains[1].Priority != "0" ||
		rs.Chains[1].Hook != "input" || rs.Chains[1].Type != "filter" || rs.Chains[1].Rules != 2 {
		t.Errorf("chain[1] %+v", rs.Chains[1])
	}
}

// A ruleset that could be read is recorded as chains, policies and rule
// counts, and the bytes are kept as evidence only while they are small and
// carry no address literal.
func TestFirewallProbeRecordsChainsAndPolicies(t *testing.T) {
	runner := probe.NewFakeRunner().
		AddTool(FirewallToolNft, "/usr/sbin/nft").
		Script(FirewallToolNft, []string{"--version"}, probe.FakeResponse{Stdout: netFixture(t, "firewall/nft-version.txt")}).
		Script(FirewallToolNft, []string{"--json", "list", "ruleset"}, probe.FakeResponse{Stdout: []byte(nftRulesetJSON)})
	cc, ev := netTestCollect(FirewallProbeID, runner)
	res := NewFirewallProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q)", res.Status, res.Reason)
	}
	fw := netArtifact(t, res, ArtifactFirewall)
	if fw.Attributes["backend_observed"] != FirewallToolNft || fw.Attributes["observation"] != observationObserved {
		t.Errorf("summary attributes %v", fw.Attributes)
	}
	if fw.Provenance.ToolVersion != "nft 1.0.9" {
		t.Errorf("tool version %q, want the version the ruleset states", fw.Provenance.ToolVersion)
	}
	table := netArtifact(t, res, "security/firewall/nft/inet/filter")
	if table.Attributes["chain_count"] != "2" || table.Attributes["rule_count"] != "2" {
		t.Errorf("table attributes %v", table.Attributes)
	}
	input := netArtifact(t, res, "security/firewall/nft/inet/filter/input")
	for k, want := range map[string]string{
		"policy": "drop", "hook": "input", "type": "filter", "priority": "0", "rule_count": "2",
	} {
		if input.Attributes[k] != want {
			t.Errorf("input chain %s = %q, want %q", k, input.Attributes[k], want)
		}
	}
	for _, a := range res.NormalizedState {
		for k, v := range a.Attributes {
			if strings.Contains(k, "rule_text") || strings.Contains(v, "iifname") {
				t.Errorf("artifact %s carries rule text: %v", a.ID, a.Attributes)
			}
		}
	}
	if names := netEvidenceNames(ev); len(names) != 2 || names[0] != "nft-list-ruleset.json" {
		t.Errorf("evidence %v, want the small address free ruleset plus the version", names)
	}
}

// A ruleset that names addresses is not persisted verbatim; the derived
// artifacts are, and a diagnostic says what happened.
func TestFirewallProbeWithholdsARulesetWithAddresses(t *testing.T) {
	withAddress := strings.Replace(nftRulesetJSON,
		`{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}`,
		`{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "203.0.113.10"}}`, 1)
	runner := probe.NewFakeRunner().
		AddTool(FirewallToolNft, "/usr/sbin/nft").
		Script(FirewallToolNft, []string{"--version"}, probe.FakeResponse{Stdout: netFixture(t, "firewall/nft-version.txt")}).
		Script(FirewallToolNft, []string{"--json", "list", "ruleset"}, probe.FakeResponse{Stdout: []byte(withAddress)})
	cc, ev := netTestCollect(FirewallProbeID, runner)
	res := NewFirewallProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured", res.Status)
	}
	if !netHasWarning(res, netDiagEvidenceWithheld, "") {
		t.Errorf("no evidence_withheld diagnostic: %v", res.Warnings)
	}
	for _, n := range netEvidenceNames(ev) {
		if n == "nft-list-ruleset.json" {
			t.Errorf("the ruleset with an address literal was persisted")
		}
	}
	if netArtifact(t, res, "security/firewall/nft/inet/filter/input").Attributes["rule_count"] != "2" {
		t.Errorf("the derived rule count must survive the withheld evidence")
	}
}

func TestParseUfwStatus(t *testing.T) {
	st, err := ParseUfwStatus([]byte(ufwStatusText))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.Status != "active" || st.Rules != 2 {
		t.Errorf("got %+v, want active with 2 rules", st)
	}
	inactive, err := ParseUfwStatus([]byte("Status: inactive\n"))
	if err != nil || inactive.Status != "inactive" || inactive.Rules != 0 {
		t.Errorf("inactive: %+v, %v", inactive, err)
	}
	if _, err := ParseUfwStatus(netFixture(t, "firewall/ufw-status.stderr.txt")); !errors.Is(err, ErrUfwStatus) {
		t.Errorf("the refusal text is not a status output: %v", err)
	}
}

// Without nft the probe falls back to ufw, and the result names ufw as the
// backend it observed.
func TestFirewallProbeFallsBackToUfw(t *testing.T) {
	runner := probe.NewFakeRunner().
		AddTool(FirewallToolUfw, "/usr/sbin/ufw").
		Script(FirewallToolUfw, []string{"--version"}, probe.FakeResponse{Stdout: netFixture(t, "firewall/ufw-version.txt")}).
		Script(FirewallToolUfw, []string{"status"}, probe.FakeResponse{Stdout: []byte(ufwStatusText)})
	cc, _ := netTestCollect(FirewallProbeID, runner)
	res := NewFirewallProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q)", res.Status, res.Reason)
	}
	fw := netArtifact(t, res, ArtifactFirewall)
	if fw.Attributes["backends_present"] != "ufw" || fw.Attributes["backend_observed"] != "ufw" {
		t.Errorf("summary attributes %v", fw.Attributes)
	}
	if fw.Provenance.ToolVersion != "ufw 0.36.2" {
		t.Errorf("tool version %q", fw.Provenance.ToolVersion)
	}
	ufw := netArtifact(t, res, artifactFirewallUfw)
	if ufw.Attributes["status"] != "active" || ufw.Attributes["rule_count"] != "2" {
		t.Errorf("ufw attributes %v", ufw.Attributes)
	}
}

// nft refuses, ufw answers: the probe reports what it observed and keeps the
// refusal visible as a partial result.
func TestFirewallProbePartialWhenOneBackendRefuses(t *testing.T) {
	runner := netFirewallRunner(t).
		Script(FirewallToolUfw, []string{"status"}, probe.FakeResponse{Stdout: []byte(ufwStatusText)})
	cc, _ := netTestCollect(FirewallProbeID, runner)
	res := NewFirewallProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "nft") {
		t.Errorf("reason %q does not name the refused backend", res.Reason)
	}
	if got := netArtifact(t, res, ArtifactFirewall).Attributes["backend_observed"]; got != "ufw" {
		t.Errorf("backend_observed %q, want ufw", got)
	}
}

func TestFirewallProbeDescriptor(t *testing.T) {
	p := NewFirewallProbe()
	if err := p.Descriptor().Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if p.Descriptor().RequiredPrivilege != probe.PrivilegeElevated {
		t.Errorf("required privilege %q, want elevated: a full ruleset needs root", p.Descriptor().RequiredPrivilege)
	}
	if got := p.RequiredTools(); len(got) != 2 || got[0] != "nft" || got[1] != "ufw" {
		t.Errorf("required tools %v", got)
	}
}
