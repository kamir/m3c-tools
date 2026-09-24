package linux

import (
	"encoding/json"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// commandsIndexPath is the machine readable index of the fixtures of this
// package.
const commandsIndexPath = "testdata/commands.json"

// commandsIndex is the part of commands.json this test reads. The file carries
// more per entry (the argv, the note, the host class); what is checked here is
// the one property a reader relies on: the index and the tree say the same
// thing about WHICH fixtures exist.
type commandsIndex struct {
	Fixtures []struct {
		Path string `json:"path"`
	} `json:"fixtures"`
}

// TestCommandsIndexCoversEveryFixture: testdata/README.md says commands.json
// holds one entry per fixture. That sentence is checked here rather than
// trusted, in both directions, because provenance that drifts from the tree is
// worse than no provenance: a fixture with no entry has no recorded argv, and
// an entry with no fixture describes a measurement nobody can look at.
func TestCommandsIndexCoversEveryFixture(t *testing.T) {
	raw, err := os.ReadFile(commandsIndexPath)
	if err != nil {
		t.Fatal(err)
	}
	var idx commandsIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("%s: %v", commandsIndexPath, err)
	}
	listed := make([]string, 0, len(idx.Fixtures))
	for _, f := range idx.Fixtures {
		if f.Path == "" {
			t.Fatalf("%s: an entry without a path", commandsIndexPath)
		}
		if slices.Contains(listed, f.Path) {
			t.Errorf("%s: %q is listed twice", commandsIndexPath, f.Path)
		}
		listed = append(listed, f.Path)
	}

	var onDisk []string
	err = filepath.WalkDir("testdata", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, "testdata"+string(filepath.Separator)))
		// The index itself and the prose beside it are not fixtures.
		if rel == "commands.json" || strings.HasSuffix(rel, "README.md") {
			return nil
		}
		onDisk = append(onDisk, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) == 0 {
		t.Fatal("no fixture found, so this test measures nothing")
	}

	slices.Sort(listed)
	slices.Sort(onDisk)
	for _, p := range onDisk {
		if !slices.Contains(listed, p) {
			t.Errorf("fixture %q has no entry in %s, so its argv is not recorded anywhere", p, commandsIndexPath)
		}
	}
	for _, p := range listed {
		if !slices.Contains(onDisk, p) {
			t.Errorf("%s names %q, which is not in the tree", commandsIndexPath, p)
		}
	}
}

// The address rule of this fixture tree, and why it is a test rather than a
// sentence in the README.
//
// A fixture carries no part of a real address. The reviewer of T-03b measured
// the two ways that rule was broken while the prose claimed it was kept: the
// host octet of a real address survived the rewrite of its prefix, and
// container bridge prefixes that both hosts carry today stood in the fixtures
// verbatim, because "a vendor default pool names no site" is a judgement and a
// judgement does not scale to the next author.
//
// The check is an ALLOWLIST and not a list of the real values. Writing the
// addresses of the two hosts into this file would publish exactly what the
// sanitization removes (playbook section 1 rule 8), so the test cannot compare
// against them. Instead every address literal in the tree must lie in a space
// that is either reserved for documentation and testing or IANA-assigned and
// universal. That is the stronger rule: an address pasted from any real host
// fails this test whatever range it came from, including the ranges a private
// network uses (10/8, 172.16/12, 192.168/16) and the unique-local IPv6 range.
var (
	// fixtureAllowedV4 are the IPv4 spaces a fixture may carry.
	fixtureAllowedV4 = []struct {
		prefix string
		reason string
	}{
		{"192.0.2.0/24", "RFC 5737 TEST-NET-1, reserved for documentation"},
		{"198.51.100.0/24", "RFC 5737 TEST-NET-2, reserved for documentation"},
		{"203.0.113.0/24", "RFC 5737 TEST-NET-3, reserved for documentation"},
		{"100.64.0.0/10", "RFC 6598 shared address space: the synthetic container networks of these fixtures, because no documentation range is large enough for a /16 bridge network"},
		{"127.0.0.0/8", "IANA loopback: a resolver at 127.0.0.53 and a listener on 127.0.0.1 are the substance of the fixture, not an identity"},
		{"0.0.0.0/32", "the unspecified address: a listener bound to it is the exposure finding"},
		{"169.254.0.0/16", "RFC 3927 IPv4 link-local: the kernel assigns it, no site chooses it"},
		{"224.0.0.0/4", "IANA multicast: assigned addresses, never a host's own"},
	}
	// fixtureAllowedV6 are the IPv6 spaces a fixture may carry.
	fixtureAllowedV6 = []struct {
		prefix string
		reason string
	}{
		{"2001:db8::/32", "RFC 3849 documentation prefix"},
		{"::/128", "the unspecified address"},
		{"::1/128", "loopback"},
		{"fe80::/10", "link-local: derived from the interface address, and the fixture MACs are synthetic"},
		{"ff00::/8", "IANA multicast"},
	}
	// fixtureAddressExceptions are the exact literals a named file may carry
	// although the rule refuses them. Each one is a string that only looks
	// like an address; the exception is per file and per literal, so a real
	// address in the same file still fails.
	fixtureAddressExceptions = map[string][]string{
		// A package version with four dot-separated numbers. The prose of
		// README.md needs no exception: it names the banned ranges in their
		// short form (10/8) and the unique-local range by name, so no line of
		// it parses as an address.
		"packages/dpkg-query-w.txt": {"1.2.5.1"},
	}
)

// fixtureAddressAllowed reports whether one literal may stand in a fixture,
// and names the space that allows it.
func fixtureAddressAllowed(lit string) (bool, string) {
	addr, err := netip.ParseAddr(lit)
	if err != nil {
		return false, "not an address"
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	allowed := fixtureAllowedV6
	if addr.Is4() {
		allowed = fixtureAllowedV4
	}
	for _, a := range allowed {
		p, err := netip.ParsePrefix(a.prefix)
		if err != nil {
			return false, "the allowlist entry " + a.prefix + " is not a prefix: " + err.Error()
		}
		if p.Contains(addr) {
			return true, a.reason
		}
	}
	return false, "no documented space contains it"
}

// fixtureAddressLiterals returns every string in b that parses as an address.
//
// It reads maximal runs of the characters an address is written with rather
// than matching a pattern, so a version number, a MAC address and a timestamp
// are rejected by the parser instead of by a regular expression that would
// have to anticipate them. A run that does not parse is not an address.
func fixtureAddressLiterals(b []byte) []string {
	var out []string
	add := func(run string) {
		if run == "" {
			return
		}
		if _, err := netip.ParseAddr(run); err == nil {
			out = append(out, run)
		}
	}
	// IPv4 candidates: runs of digits and dots.
	var run strings.Builder
	for _, r := range string(b) {
		if (r >= '0' && r <= '9') || r == '.' {
			run.WriteRune(r)
			continue
		}
		add(run.String())
		run.Reset()
	}
	add(run.String())
	// IPv6 candidates: runs of hex digits, colons and dots, with at least two
	// colons. One colon is a port, a MAC has five and does not parse.
	run.Reset()
	isHex := func(r rune) bool {
		return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
	}
	flush := func() {
		s := run.String()
		run.Reset()
		if strings.Count(s, ":") >= 2 {
			add(s)
		}
	}
	for _, r := range string(b) {
		if isHex(r) || r == ':' || r == '.' {
			run.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// TestFixturesCarryNoRealAddress: every address literal of the whole fixture
// tree lies in a documented space (see the rule above and the section "The
// address rule" of testdata/README.md).
//
// The first half of the test measures the check itself: a search that finds
// nothing proves nothing until it has been shown to find a planted occurrence.
// The planted values are private-range addresses that are NOT on any host of
// this project, so the proof does not reintroduce what the sanitization
// removed.
func TestFixturesCarryNoRealAddress(t *testing.T) {
	for _, lit := range []string{
		"192.168.7.42", "10.99.0.1", "172.20.5.5", "172.31.255.254",
		"fc00:1234:5678:9abc::1", "fd00::2", "8.8.4.4", "2a00:1450:4001:80f::200e",
	} {
		if ok, why := fixtureAddressAllowed(lit); ok {
			t.Errorf("the check accepts the planted address %q (%s), so it would not have caught it in a fixture", lit, why)
		}
	}
	for _, lit := range []string{
		"203.0.113.10", "198.51.100.20", "192.0.2.1", "100.64.0.1",
		"127.0.0.53", "0.0.0.0", "169.254.0.0",
		"2001:db8::53", "::", "::1", "fe80::42:aff:fe00:4",
	} {
		if ok, _ := fixtureAddressAllowed(lit); !ok {
			t.Errorf("the check refuses %q, which the fixtures are allowed to carry", lit)
		}
	}

	var scanned int
	err := filepath.WalkDir("testdata", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p) // #nosec G304 -- a path from the fixture tree of this test
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, "testdata"+string(filepath.Separator)))
		exempt := fixtureAddressExceptions[rel]
		for _, lit := range fixtureAddressLiterals(raw) {
			scanned++
			if slices.Contains(exempt, lit) {
				continue
			}
			if ok, why := fixtureAddressAllowed(lit); !ok {
				t.Errorf("%s carries the address %q: %s. A fixture carries no part of a real address; see the address rule in testdata/README.md", rel, lit, why)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no address literal was found anywhere, so this test measures nothing")
	}
}
