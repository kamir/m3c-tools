package evaluation

// E2 — Kit verify on an AIR-GAPPED host (SPEC-0280 §2; SPEC-0276 R4.3).
// E9 — Kit SIZE + reproducibility (SPEC-0280 §2; SPEC-0276 R4.3).
//
// Both drivers exercise the REAL shipped CLI end-to-end: they build the `skillctl`
// binary, mint a deterministic signed-bundle fixture, run
// `skillctl export-verification-kit`, then verify the kit OFFLINE with
// `skillctl verify` (the same command the kit's verify.sh runs).
//
// E2 — air-gap proof. We count OUTBOUND NETWORK ATTEMPTS by routing every proxy
// env var (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY + lowercase) at a localhost SENTINEL
// listener and pointing NO_PROXY nowhere, so ANY attempt by the verifier to make
// an HTTP(S) call would land on the sentinel and be COUNTED. The kit verify is
// pinned-mode (offline by construction), so the assertion is: wall-clock recorded
// AND sentinel connection count == 0. (The sentinel is a strict upper bound on
// HTTP egress; a raw non-proxied dial would also be visible because the verifier
// has no other endpoint configured — it never reads ER1/registry config in the
// kit path.) The README documents the privileged strace/dtruss syscall variant
// for an even stronger guarantee.
//
// E9 — size + byte-reproducibility. We record the kit's total byte size, then
// export it a SECOND time from the same deterministic fixture into a fresh dir
// and assert every file is byte-identical (the kit is reproducible from the
// signed inputs — no embedded timestamps/nondeterminism).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// repoRoot returns the module root (parent of the evaluation package dir).
func repoRoot(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd) // evaluation/ → repo root
}

// buildSkillctl compiles cmd/skillctl into a temp dir and returns the binary path.
func buildSkillctl(t testing.TB) string {
	t.Helper()
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "skillctl")
	if runtime.GOOS == "windows" {
		bin += ".exe" // Windows needs the .exe suffix to exec the built binary
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/skillctl")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build skillctl: %v\n%s", err, out)
	}
	return bin
}

// mintFixture runs the deterministic kit-fixture issuer into dir and returns it.
func mintFixture(t testing.TB, dir string) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("go", "run", "evaluation/scripts/mint_kit_fixture.go", dir)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mint fixture: %v\n%s", err, out)
	}
}

// exportKit runs `skillctl export-verification-kit` against a fixture dir.
func exportKit(t testing.TB, bin, fixtureDir, outDir string) {
	t.Helper()
	skb := filepath.Join(fixtureDir, "eval-kit-skill@1.0.0.skb")
	tr := filepath.Join(fixtureDir, "trust-roots.pinned.yaml")
	cmd := exec.Command(bin, "export-verification-kit",
		"--bundle", skb,
		"--trust-roots", tr,
		"--out", outDir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("export-verification-kit: %v\n%s", err, out)
	}
}

// TestE2KitAirGap exports a kit and verifies it offline, asserting ZERO outbound
// network attempts and recording the wall-clock.
func TestE2KitAirGap(t *testing.T) {
	requireEval(t)
	bin := buildSkillctl(t)

	fixture := t.TempDir()
	mintFixture(t, fixture)
	kitDir := filepath.Join(t.TempDir(), "kit")
	exportKit(t, bin, fixture, kitDir)

	// Sentinel: a localhost listener that COUNTS any inbound connection. We route
	// every proxy env var at it so any HTTP(S) egress the verifier attempts is
	// counted here. Zero connections == air-gapped for the kit verify path.
	var hits int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sentinel listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&hits, 1)
			_ = c.Close()
		}
	}()
	proxy := "http://" + ln.Addr().String()

	skb := filepath.Join(kitDir, "eval-kit-skill@1.0.0.skb")
	trustRoots := filepath.Join(kitDir, "trust-roots.pinned.yaml")

	cmd := exec.Command(bin, "verify", "--bundle", skb, "--trust-roots", trustRoots)
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy,
		"http_proxy="+proxy, "https_proxy="+proxy, "all_proxy="+proxy,
		"NO_PROXY=", "no_proxy=",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	start := time.Now()
	err = cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("kit verify failed (exit): %v\n%s", err, out.String())
	}

	netCalls := atomic.LoadInt64(&hits)
	t.Logf("E2 kit air-gap verify: wall_clock=%.4fms net_calls=%d\n%s", ms(elapsed), netCalls, out.String())
	if netCalls != 0 {
		t.Errorf("E2 FAIL: kit verify made %d outbound network attempts (want 0)", netCalls)
	}

	recordPop(t, "E2", "kit-air-gap", "wall_clock_ms", round4(ms(elapsed)), "synthetic",
		"`skillctl verify` over an exported kit, all proxy env routed at a sentinel")
	recordPop(t, "E2", "kit-air-gap", "net_calls", fmt.Sprintf("%d", netCalls), "synthetic",
		"outbound HTTP(S) attempts counted by the localhost sentinel; MUST be 0")
}

// dirFingerprint returns a sorted map of relative path → sha256 of contents, and
// the total byte size, for a kit directory.
func dirFingerprint(t testing.TB, dir string) (map[string]string, int64) {
	t.Helper()
	fps := map[string]string{}
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read kit dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		sum := sha256.Sum256(data)
		fps[e.Name()] = hex.EncodeToString(sum[:])
		total += int64(len(data))
	}
	return fps, total
}

// TestE9KitSizeReproducibility exports the kit twice from the same deterministic
// fixture and records the byte size + whether the two kits are byte-identical.
func TestE9KitSizeReproducibility(t *testing.T) {
	requireEval(t)
	bin := buildSkillctl(t)

	fixture := t.TempDir()
	mintFixture(t, fixture)

	kit1 := filepath.Join(t.TempDir(), "kit1")
	kit2 := filepath.Join(t.TempDir(), "kit2")
	exportKit(t, bin, fixture, kit1)
	exportKit(t, bin, fixture, kit2)

	fp1, size1 := dirFingerprint(t, kit1)
	fp2, size2 := dirFingerprint(t, kit2)

	identical := size1 == size2 && len(fp1) == len(fp2)
	var diffs []string
	if identical {
		names := make([]string, 0, len(fp1))
		for n := range fp1 {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if fp1[n] != fp2[n] {
				identical = false
				diffs = append(diffs, n)
			}
		}
	}

	t.Logf("E9 kit size=%d bytes (%d files); reproducible=%v diffs=%v", size1, len(fp1), identical, diffs)
	record(t, "E9", "kit-size", "bytes", fmt.Sprintf("%d", size1),
		"exported verification-kit total size (%d files)", len(fp1))
	repro := "yes"
	if !identical {
		repro = "no"
	}
	record(t, "E9", "kit-reproducibility", "byte_identical", repro,
		"two exports from the same deterministic signed fixture compared file-by-file")
	if !identical {
		t.Errorf("E9 FAIL: kit not byte-reproducible; differing files: %v", diffs)
	}
}
