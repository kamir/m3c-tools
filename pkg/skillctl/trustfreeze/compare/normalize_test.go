package compare

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// mustCompareWith is mustCompare with an explicit normalization rule set, so a
// test can show what an older rule set answers for the same two bundles.
func mustCompareWith(t testing.TB, baseline, current *trustfreeze.Bundle, ruleSetID string) Diff {
	t.Helper()
	d, err := Compare(context.Background(), baseline, current, CompareOptions{RuleSetID: ruleSetID})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// These constants pin the shipped rule sets. Changing what counts as
// volatile must come with a new rule set id (SPEC-0469 R4), never with an edit
// of a published one; these constants make such an edit fail loudly.
const (
	normalizeV1Digest = "sha256:9813f9b495979bf3b5103a1816d07aab19a2bd95fb05491197b614bf28e575d9"
	normalizeV2Digest = "sha256:48b02614a4e2139449d49603519d74d0d1c3d68b0677f70444eeb2a2dacfb4bb"
)

func TestRuleSetV1(t *testing.T) {
	rs, err := LoadRuleSet(RuleSetNormalizeV1)
	if err != nil {
		t.Fatal(err)
	}
	if rs.ID != RuleSetNormalizeV1 {
		t.Fatalf("rule set = %q", rs.ID)
	}
	// TF04-AC1 categories: timestamps, durations, pid, uptime.
	for _, k := range []string{"pid", "uptime_seconds", "started_at", "duration_ms", "boot_time"} {
		if !slices.Contains(rs.VolatileAttributes, k) {
			t.Errorf("volatile_attributes lacks %q", k)
		}
	}
	// Nothing that describes the state itself is volatile.
	for _, k := range []string{"os_version", "version", "hostname", "kernel_release"} {
		if slices.Contains(rs.VolatileAttributes, k) {
			t.Errorf("volatile_attributes contains state attribute %q", k)
		}
	}
	if !slices.Equal(rs.VolatileFields, []string{"provenance.observed_at"}) {
		t.Fatalf("volatile_fields = %q", rs.VolatileFields)
	}
	d, err := rs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d != normalizeV1Digest {
		t.Fatalf("normalize/v1 digest = %s, pinned %s: add a new rule set id instead of editing v1", d, normalizeV1Digest)
	}
}

// SPEC-0471 TF06-R3, T-03b playbook B5: v2 is the default and adds exactly the
// two volatile values of the Linux network probes on top of v1. v1 stays
// shipped and unchanged, so a diff that names it stays readable.
func TestRuleSetV2IsDefaultAndExtendsV1(t *testing.T) {
	def, err := LoadRuleSet("")
	if err != nil {
		t.Fatal(err)
	}
	if def.ID != RuleSetNormalizeV2 || DefaultRuleSetID != RuleSetNormalizeV2 {
		t.Fatalf("default rule set = %q", def.ID)
	}
	if !slices.Equal(RuleSetIDs(), []string{RuleSetNormalizeV1, RuleSetNormalizeV2}) {
		t.Fatalf("shipped rule sets %q", RuleSetIDs())
	}
	v1, err := LoadRuleSet(RuleSetNormalizeV1)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(def.VolatileFields, v1.VolatileFields) {
		t.Fatalf("v2 volatile_fields = %q, v1 %q", def.VolatileFields, v1.VolatileFields)
	}
	added := []string{}
	for _, k := range def.VolatileAttributes {
		if !slices.Contains(v1.VolatileAttributes, k) {
			added = append(added, k)
		}
	}
	if !slices.Equal(added, []string{"current_dns_server", "route_metric"}) {
		t.Fatalf("v2 adds %q", added)
	}
	for _, k := range v1.VolatileAttributes {
		if !slices.Contains(def.VolatileAttributes, k) {
			t.Errorf("v2 dropped the volatile attribute %q of v1", k)
		}
	}
	// The values that carry the finding of the two network probes stay
	// compared: a new gateway, a new resolver list or a route that changed
	// its device is drift, and no rule set may hide it.
	for _, k := range []string{"gateway", "destination", "device", "dns_servers", "search_domains",
		"nameservers", "dns_over_tls", "dnssec_mode", "default_route", "address_class", "sha256"} {
		if slices.Contains(def.VolatileAttributes, k) {
			t.Errorf("volatile_attributes contains the state attribute %q", k)
		}
	}
	d, err := def.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d != normalizeV2Digest {
		t.Fatalf("normalize/v2 digest = %s, pinned %s: add a new rule set id instead of editing v2", d, normalizeV2Digest)
	}
}

// A CRLF checkout of the embedded file gives the same rule set and digest.
func TestRuleSetCRLFCheckoutSameDigest(t *testing.T) {
	orig := ruleSetFiles[RuleSetNormalizeV1]
	t.Cleanup(func() { ruleSetFiles[RuleSetNormalizeV1] = orig })
	lf, err := LoadRuleSet(RuleSetNormalizeV1)
	if err != nil {
		t.Fatal(err)
	}
	ruleSetFiles[RuleSetNormalizeV1] = bytes.ReplaceAll(bytes.ReplaceAll(orig, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	crlf, err := LoadRuleSet(RuleSetNormalizeV1)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := lf.Digest()
	b, _ := crlf.Digest()
	if a != b {
		t.Fatalf("CRLF digest %s != LF digest %s", b, a)
	}
}

func TestRuleSetValidate(t *testing.T) {
	cases := map[string]RuleSet{
		"empty id":                  {VolatileFields: []string{}, VolatileAttributes: []string{}},
		"unknown field":             {ID: "x", VolatileFields: []string{"provenance.color"}},
		"state is never volatile":   {ID: "x", VolatileFields: []string{"state"}},
		"attributes are not fields": {ID: "x", VolatileFields: []string{"attributes"}},
		"unsorted":                  {ID: "x", VolatileAttributes: []string{"uptime", "pid"}},
		"duplicate":                 {ID: "x", VolatileAttributes: []string{"pid", "pid"}},
		"empty entry":               {ID: "x", VolatileAttributes: []string{""}},
	}
	for name, rs := range cases {
		if err := rs.Validate(); !errors.Is(err, ErrUnknownRuleSet) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	if _, err := LoadRuleSet("trust-freeze/normalize/v3"); !errors.Is(err, ErrUnknownRuleSet) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestNormalizeAttributesCopies(t *testing.T) {
	rs, err := LoadRuleSet("")
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]string{"pid": "1", "version": "2"}
	out := rs.NormalizeAttributes(in)
	if len(out) != 1 || out["version"] != "2" || len(in) != 2 {
		t.Fatalf("in %v out %v", in, out)
	}
	if got := rs.NormalizeAttributes(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil map -> %v", got)
	}
	if !slices.IsSorted(ComparedFields()) || !slices.Contains(ComparedFields(), "state") {
		t.Fatalf("ComparedFields = %q", ComparedFields())
	}
}

// networkFixture is baseFixture plus one route artifact and one resolver link
// artifact, the two artifact families T-03b added. metric is the route metric
// and current is the server systemd-resolved is querying at the moment.
func networkFixture(noise int, metric, current string) fixture {
	f := baseFixture(testTime, noise)
	obs := trustfreeze.FormatTime(testTime)
	route := artifact("network/route/ipv4/main/eth0/default", "network-route",
		trustfreeze.StateObserved, trustfreeze.ConfidenceProven, obs, map[string]string{
			"address_family": "ipv4", "destination": "default", "device": "eth0", "table": "main",
			"default_route": "yes", "gateway": "203.0.113.1", "protocol": "dhcp",
			"route_metric": metric,
		})
	route.Source = "linux.network.routes"
	link := artifact("dns/link/eth0", "dns-link",
		trustfreeze.StateObserved, trustfreeze.ConfidenceProven, obs, map[string]string{
			"interface": "eth0", "resolves": "yes", "server_count": "2",
			"dns_servers": "203.0.113.53,198.51.100.53", "dnssec_mode": "no",
			"current_dns_server": current,
		})
	link.Source = "linux.dns"
	f.arts = append(f.arts, route, link)
	f.required = append(f.required, "linux.dns", "linux.network.routes")
	f.results = append(f.results,
		probeResult("linux.dns", trustfreeze.StatusCaptured, "", testTime, int64(11+noise)),
		probeResult("linux.network.routes", trustfreeze.StatusCaptured, "", testTime, int64(13+noise)))
	return f
}

// T-03b playbook B5: the route metric the network stack rewrote and the
// resolver systemd-resolved happens to be querying are normalized away, so
// neither reads as drift. The two planted controls prove the same comparison
// still sees a new gateway and a new resolver list: the rule set removes the
// volatile value beside the finding, never the finding.
func TestCompareRouteMetricAndCurrentResolverAreNotDrift(t *testing.T) {
	bl := memBundle(t, trustfreeze.KindBaseline, networkFixture(0, "100", "203.0.113.53"))
	later := networkFixture(9, "1024", "198.51.100.53")
	d := mustCompare(t, bl, memBundle(t, trustfreeze.KindCapture, later))
	if len(d.Changes) != 0 {
		t.Fatalf("a changed route metric or current resolver caused drift: %q", kinds(d))
	}

	gw := networkFixture(9, "1024", "198.51.100.53")
	gw.arts[4].Attributes["gateway"] = "198.51.100.1"
	d = mustCompare(t, bl, memBundle(t, trustfreeze.KindCapture, gw))
	if got := kinds(d); !slices.Equal(got, []string{"changed:network/route/ipv4/main/eth0/default"}) {
		t.Fatalf("gateway control: %q", got)
	}
	if !slices.Equal(d.Changes[0].ChangedAttributes, []string{"gateway"}) {
		t.Fatalf("gateway control attributes = %q", d.Changes[0].ChangedAttributes)
	}

	srv := networkFixture(9, "1024", "198.51.100.53")
	srv.arts[5].Attributes["dns_servers"] = "203.0.113.53,198.51.100.53,203.0.113.54"
	d = mustCompare(t, bl, memBundle(t, trustfreeze.KindCapture, srv))
	if got := kinds(d); !slices.Equal(got, []string{"changed:dns/link/eth0"}) {
		t.Fatalf("resolver control: %q", got)
	}
	if !slices.Equal(d.Changes[0].ChangedAttributes, []string{"dns_servers"}) {
		t.Fatalf("resolver control attributes = %q", d.Changes[0].ChangedAttributes)
	}

	// Under v1 the same pair of captures is drift on both artifacts: that is
	// what the new rule set changed, and why it needed a new id.
	v1 := mustCompareWith(t, bl, memBundle(t, trustfreeze.KindCapture, later), RuleSetNormalizeV1)
	if got := kinds(v1); !slices.Equal(got, []string{"changed:dns/link/eth0", "changed:network/route/ipv4/main/eth0/default"}) {
		t.Fatalf("under v1: %q", got)
	}
}
