package trustfreeze

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

func newTestWriter(t *testing.T, kind Kind) *Writer {
	t.Helper()
	w, err := NewWriter(filepath.Join(t.TempDir(), "out"), WriterOptions{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abort() })
	return w
}

func TestWriterRefusesPaths(t *testing.T) {
	cases := []struct {
		name  string
		kind  Kind
		write func(w *Writer) error
		want  error
	}{
		{"backslash path", KindCapture, func(w *Writer) error { return w.WriteJSON(`probes\a.json`, 1) }, ErrBadPath},
		{"dot prefix", KindCapture, func(w *Writer) error { return w.WriteJSON("./capture.json", 1) }, ErrBadPath},
		{"absolute", KindCapture, func(w *Writer) error { return w.WriteJSON("/tmp/x.json", 1) }, ErrBadPath},
		{"traversal", KindCapture, func(w *Writer) error { return w.WriteJSON("../x.json", 1) }, ErrBadPath},
		{"manifest reserved", KindCapture, func(w *Writer) error { return w.WriteJSON(ManifestFile, 1) }, ErrReservedPath},
		{"signature reserved", KindBaseline, func(w *Writer) error { return w.WriteJSON(SignatureFile, 1) }, ErrReservedPath},
		{"signatures dir reserved", KindBaseline, func(w *Writer) error { return w.WriteJSON("signatures/x.json", 1) }, ErrReservedPath},
		{"approval in capture", KindCapture, func(w *Writer) error { return w.WriteJSON(ApprovalFile, 1) }, ErrReservedPath},
		{"approval in diff", KindDiff, func(w *Writer) error { return w.WriteJSON(ApprovalFile, 1) }, ErrReservedPath},
		{"evidence through WriteJSON", KindCapture, func(w *Writer) error { return w.WriteJSON("evidence/common.identity/x", 1) }, ErrReservedPath},
		{"evidence outside evidence dir", KindCapture, func(w *Writer) error {
			_, err := w.WriteEvidence("probes/raw.txt", redact.Redacted{})
			return err
		}, ErrReservedPath},
		{"evidence too deep", KindCapture, func(w *Writer) error {
			_, err := w.WriteEvidence("evidence/common.identity/a/b", redact.Redacted{})
			return err
		}, ErrReservedPath},
		{"evidence bad probe id", KindCapture, func(w *Writer) error {
			_, err := w.WriteEvidence("evidence/Common/x", redact.Redacted{})
			return err
		}, ErrInvalidID},
		{"float value", KindCapture, func(w *Writer) error { return w.WriteJSON("x.json", map[string]any{"f": 0.5}) }, ErrNotCanonical},
		{"case-only duplicate", KindCapture, func(w *Writer) error {
			if err := w.WriteJSON("state/device.json", StateDoc{}); err != nil {
				return err
			}
			return w.WriteJSON("state/Device.json", StateDoc{})
		}, ErrBadPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWriter(t, tc.kind)
			if err := tc.write(w); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("approval in baseline is allowed", func(t *testing.T) {
		w := newTestWriter(t, KindBaseline)
		if err := w.WriteJSON(ApprovalFile, map[string]string{"reviewer": "id:charlie@example"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWriterEvidence(t *testing.T) {
	w := newTestWriter(t, KindCapture)
	ref, err := w.WriteEvidence("evidence/common.identity/stdout", redact.Redacted{})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Path != "evidence/common.identity/stdout" || ref.Size != 0 || ref.SHA256 != SHA256Hex(nil) {
		t.Fatalf("ref = %+v", ref)
	}
	if _, err := w.WriteEvidence("evidence/common.identity/stdout", redact.Redacted{}); err == nil {
		t.Fatal("writing the same path twice must fail")
	}
}

func TestWriterFinalize(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "cap")
	w, err := NewWriter(target, WriterOptions{Kind: KindCapture})
	if err != nil {
		t.Fatal(err)
	}
	writeCaptureFiles(t, w, threeProbes...)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the target must not exist before Finalize")
	}
	m, err := w.Finalize(testHeader(KindCapture))
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyDir(target); !res.OK || res.ContentDigest != m.ContentDigest {
		t.Fatalf("finalized bundle does not verify: %s", describeFailures(res))
	}
	on := readManifestFile(t, target)
	if !reflect.DeepEqual(on, m) {
		t.Fatal("returned manifest differs from manifest.json")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "cap" {
		t.Fatalf("staging directory left behind: %v", entries)
	}
	if err := w.WriteJSON("late.json", 1); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("write after Finalize = %v", err)
	}
	if _, err := w.Finalize(testHeader(KindCapture)); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("second Finalize = %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("Abort after Finalize = %v", err)
	}
}

func TestWriterFinalizeRefusesBadContent(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, w *Writer)
		want  error
	}{
		{"no capture.json", func(t *testing.T, w *Writer) {
			if err := w.WriteJSON(StateDeviceFile, StateDoc{}); err != nil {
				t.Fatal(err)
			}
		}, ErrBadCapture},
		{"lying completeness", func(t *testing.T, w *Writer) {
			r := sampleProbeResult("common.identity", StatusPermissionDenied)
			doc := sampleCaptureDoc([]string{"common.identity"}, []ProbeResult{r})
			doc.Completeness.Status = CompletenessComplete
			doc.Completeness.Gaps = []CompletenessGap{}
			if err := w.WriteJSON(CaptureFile, doc); err != nil {
				t.Fatal(err)
			}
		}, ErrCompletenessMismatch},
		{"subject differs from manifest", func(t *testing.T, w *Writer) {
			doc := sampleCaptureDoc(nil, nil)
			doc.Subject.ID = SubjectID("linux", "host-b.example")
			if err := w.WriteJSON(CaptureFile, doc); err != nil {
				t.Fatal(err)
			}
		}, ErrBadCapture},
		{"capture schema v2", func(t *testing.T, w *Writer) {
			doc := sampleCaptureDoc(nil, nil)
			doc.SchemaVersion = "trust-freeze/capture/v2"
			if err := w.WriteJSON(CaptureFile, doc); err != nil {
				t.Fatal(err)
			}
		}, ErrUnknownSchema},
		{"non-canonical capture time", func(t *testing.T, w *Writer) {
			doc := sampleCaptureDoc(nil, nil)
			doc.Capture.StartedAt = "2026-01-02T04:04:05+01:00"
			if err := w.WriteJSON(CaptureFile, doc); err != nil {
				t.Fatal(err)
			}
		}, ErrBadTime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			target := filepath.Join(parent, "cap")
			w, err := NewWriter(target, WriterOptions{Kind: KindCapture})
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(t, w)
			if _, err := w.Finalize(testHeader(KindCapture)); !errors.Is(err, tc.want) {
				t.Fatalf("Finalize = %v, want %v", err, tc.want)
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 0 {
				t.Fatalf("failed Finalize left %v behind", entries)
			}
		})
	}
}

func TestWriterKindFinalizeRules(t *testing.T) {
	if _, err := newTestWriter(t, KindBaseline).Finalize(testHeader(KindBaseline)); !errors.Is(err, ErrReservedPath) {
		t.Fatalf("baseline via Finalize = %v", err)
	}
	sign := func(Manifest) (any, error) { return map[string]string{}, nil }
	if _, err := newTestWriter(t, KindCapture).FinalizeSigned(testHeader(KindCapture), sign); !errors.Is(err, ErrReservedPath) {
		t.Fatalf("capture via FinalizeSigned = %v", err)
	}
	if _, err := newTestWriter(t, KindBaseline).FinalizeSigned(testHeader(KindBaseline), nil); err == nil {
		t.Fatal("FinalizeSigned without a sign function must fail")
	}
	w := newTestWriter(t, KindCapture)
	writeCaptureFiles(t, w, "common.identity")
	if _, err := w.Finalize(testHeader(KindDiff)); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("header kind mismatch = %v", err)
	}
	if _, err := NewWriter(filepath.Join(t.TempDir(), "x"), WriterOptions{Kind: "snapshot"}); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind = %v", err)
	}
}

func TestWriterSignFailureLeavesNothing(t *testing.T) {
	parent := t.TempDir()
	capDir, capM := newCapture(t, parent, "cap", "common.identity")
	w, err := NewWriter(filepath.Join(parent, "base"), WriterOptions{Kind: KindBaseline})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range capM.Files {
		if err := w.CopyManifestedFile(capDir, capM, f.Path); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteJSON(ApprovalFile, map[string]string{"reviewer": "id:charlie@example"}); err != nil {
		t.Fatal(err)
	}
	_, err = w.FinalizeSigned(testHeader(KindBaseline), func(Manifest) (any, error) { return nil, errors.New("key unavailable") })
	if err == nil || !strings.Contains(err.Error(), "key unavailable") {
		t.Fatalf("FinalizeSigned = %v", err)
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 || entries[0].Name() != "cap" {
		t.Fatalf("failed signing left %v behind", entries)
	}
}

func TestCopyManifestedFileChecksSource(t *testing.T) {
	parent := t.TempDir()
	capDir, capM := newCapture(t, parent, "cap", "common.identity")
	writeRaw(t, capDir, CaptureFile, []byte("tampered after verification\n"))
	w := newTestWriter(t, KindBaseline)
	if err := w.CopyManifestedFile(capDir, capM, CaptureFile); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("copy of a tampered file = %v", err)
	}
	if err := w.CopyManifestedFile(capDir, capM, "not/listed.json"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("copy of an unlisted file = %v", err)
	}
}

func TestWriterTargets(t *testing.T) {
	t.Run("missing parent", func(t *testing.T) {
		if _, err := NewWriter(filepath.Join(t.TempDir(), "a", "b"), WriterOptions{Kind: KindCapture}); err == nil {
			t.Fatal("a missing parent must be an error")
		}
	})
	t.Run("empty target directory is replaced", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Mkdir(filepath.Join(parent, "cap"), 0o700); err != nil {
			t.Fatal(err)
		}
		dir, _ := newCapture(t, parent, "cap", "common.identity")
		if res := VerifyDir(dir); !res.OK {
			t.Fatal(describeFailures(res))
		}
	})
	t.Run("non-empty target without force", func(t *testing.T) {
		parent := t.TempDir()
		writeRaw(t, parent, "cap/keep.txt", []byte("keep"))
		if _, err := NewWriter(filepath.Join(parent, "cap"), WriterOptions{Kind: KindCapture}); !errors.Is(err, ErrTargetNotEmpty) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("target is a file", func(t *testing.T) {
		parent := t.TempDir()
		writeRaw(t, parent, "cap", []byte("x"))
		if _, err := NewWriter(filepath.Join(parent, "cap"), WriterOptions{Kind: KindCapture, Force: true}); !errors.Is(err, ErrTargetNotEmpty) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("force refuses a non-bundle directory", func(t *testing.T) {
		parent := t.TempDir()
		writeRaw(t, parent, "cap/keep.txt", []byte("keep"))
		if _, err := NewWriter(filepath.Join(parent, "cap"), WriterOptions{Kind: KindCapture, Force: true}); !errors.Is(err, ErrTargetNotEmpty) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("force replaces a capture", func(t *testing.T) {
		parent := t.TempDir()
		dir, first := newCapture(t, parent, "cap", "common.identity")
		w, err := NewWriter(dir, WriterOptions{Kind: KindCapture, Force: true})
		if err != nil {
			t.Fatal(err)
		}
		writeCaptureFiles(t, w, threeProbes...)
		second, err := w.Finalize(testHeader(KindCapture))
		if err != nil {
			t.Fatal(err)
		}
		if second.ContentDigest == first.ContentDigest {
			t.Fatal("replacement did not change the bundle")
		}
		if res := VerifyDir(dir); !res.OK || res.ContentDigest != second.ContentDigest {
			t.Fatal("replaced bundle does not verify as the new one")
		}
		entries, _ := os.ReadDir(parent)
		if len(entries) != 1 {
			t.Fatalf("replacement left %v behind", entries)
		}
	})
	t.Run("force never replaces a baseline", func(t *testing.T) {
		parent := t.TempDir()
		capDir, capM := newCapture(t, parent, "cap", "common.identity")
		base := filepath.Join(parent, "base")
		newBaseline(t, capDir, capM, base)
		for _, kind := range []Kind{KindCapture, KindBaseline} {
			if _, err := NewWriter(base, WriterOptions{Kind: kind, Force: true}); !errors.Is(err, ErrUnsafeTarget) {
				t.Fatalf("kind %s over a baseline = %v", kind, err)
			}
		}
	})
	// SPEC-0467 section 5.6: --force replaces only a trust-freeze bundle.
	// A planted or copied manifest.json does not make a directory one: user
	// files next to it must survive.
	t.Run("force refuses a directory with a copied manifest", func(t *testing.T) {
		parent := t.TempDir()
		src, _ := newCapture(t, parent, "src", "common.identity")
		mb, err := os.ReadFile(filepath.Join(src, ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(parent, "victim")
		writeRaw(t, victim, "precious.txt", []byte("keep me"))
		writeRaw(t, victim, "notes/todo.md", []byte("keep me too"))
		writeRaw(t, victim, ManifestFile, mb)
		before := hashTree(t, victim)
		if _, err := NewWriter(victim, WriterOptions{Kind: KindCapture, Force: true}); !errors.Is(err, ErrTargetNotEmpty) {
			t.Fatalf("got %v, want ErrTargetNotEmpty", err)
		}
		if !reflect.DeepEqual(before, hashTree(t, victim)) {
			t.Fatal("the refused target was modified")
		}
	})
	t.Run("force refuses a two-key planted manifest", func(t *testing.T) {
		parent := t.TempDir()
		victim := filepath.Join(parent, "victim")
		writeRaw(t, victim, "precious.txt", []byte("keep me"))
		writeRaw(t, victim, ManifestFile, []byte(`{"schema_version":"trust-freeze/manifest/v1","kind":"capture"}`))
		if _, err := NewWriter(victim, WriterOptions{Kind: KindCapture, Force: true}); !errors.Is(err, ErrTargetNotEmpty) {
			t.Fatalf("got %v, want ErrTargetNotEmpty", err)
		}
	})
	t.Run("force refuses a capture that carries unlisted files", func(t *testing.T) {
		parent := t.TempDir()
		dir, _ := newCapture(t, parent, "cap", "common.identity")
		writeRaw(t, dir, "precious.txt", []byte("keep me"))
		if _, err := NewWriter(dir, WriterOptions{Kind: KindCapture, Force: true}); !errors.Is(err, ErrTargetNotEmpty) {
			t.Fatalf("got %v, want ErrTargetNotEmpty", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "precious.txt")); err != nil {
			t.Fatalf("user file gone: %v", err)
		}
	})
	t.Run("force refuses a bundle of another kind", func(t *testing.T) {
		parent := t.TempDir()
		dir, _ := newCapture(t, parent, "cap", "common.identity")
		if _, err := NewWriter(dir, WriterOptions{Kind: KindDiff, Force: true}); !errors.Is(err, ErrUnsafeTarget) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("home root and its ancestors", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "home", "alice")
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{home, filepath.Dir(home)} {
			if _, err := NewWriter(target, WriterOptions{Kind: KindCapture, Force: true, HomeRoot: home}); !errors.Is(err, ErrUnsafeTarget) {
				t.Fatalf("target %s = %v", target, err)
			}
		}
		w, err := NewWriter(filepath.Join(home, "bundles-cap"), WriterOptions{Kind: KindCapture, HomeRoot: home})
		if err != nil {
			t.Fatalf("a target inside the home root must be allowed: %v", err)
		}
		_ = w.Abort()
	})
	t.Run("filesystem root", func(t *testing.T) {
		root := string(filepath.Separator)
		if runtime.GOOS == "windows" {
			root = filepath.VolumeName(t.TempDir()) + `\`
		}
		if _, err := NewWriter(root, WriterOptions{Kind: KindCapture, Force: true}); !errors.Is(err, ErrUnsafeTarget) {
			t.Fatalf("root %q = %v", root, err)
		}
	})
	// TF05-R2, SPEC-0466 section 5.7: a new bundle is never written inside an
	// existing trust-freeze bundle, which would then carry unlisted files and
	// fail its own verification for good.
	t.Run("target inside an existing bundle", func(t *testing.T) {
		parent := t.TempDir()
		capDir, capM := newCapture(t, parent, "cap", "common.identity")
		base := filepath.Join(parent, "base")
		newBaseline(t, capDir, capM, base)
		for _, target := range []string{
			filepath.Join(base, "d"),
			filepath.Join(base, "evidence", "d"),
			filepath.Join(base, "evidence", "common.identity", "d"),
			filepath.Join(capDir, "state", "c"),
		} {
			for _, kind := range []Kind{KindCapture, KindBaseline, KindDiff} {
				if _, err := NewWriter(target, WriterOptions{Kind: kind}); !errors.Is(err, ErrUnsafeTarget) {
					t.Fatalf("kind %s at %s = %v, want ErrUnsafeTarget", kind, target, err)
				}
			}
		}
		for _, dir := range []string{base, capDir} {
			if res := VerifyDir(dir); !res.OK {
				t.Fatalf("%s no longer verifies: %s", dir, describeFailures(res))
			}
		}
		// Through a symlinked parent as well.
		link := filepath.Join(parent, "link")
		if err := os.Symlink(base, link); err == nil {
			if _, err := NewWriter(filepath.Join(link, "d"), WriterOptions{Kind: KindDiff}); !errors.Is(err, ErrUnsafeTarget) {
				t.Fatalf("through a symlink = %v, want ErrUnsafeTarget", err)
			}
		}
		// A manifest.json of some other tool is no trust-freeze bundle.
		other := filepath.Join(parent, "webapp")
		writeRaw(t, other, ManifestFile, []byte(`{"name":"app","version":"1"}`))
		w, err := NewWriter(filepath.Join(other, "tf"), WriterOptions{Kind: KindDiff})
		if err != nil {
			t.Fatalf("a foreign manifest.json must not block: %v", err)
		}
		_ = w.Abort()
		if got, err := EnclosingBundle(filepath.Join(base, "evidence", "x")); err != nil || got == "" {
			t.Fatalf("EnclosingBundle = %q, %v; want the baseline", got, err)
		}
	})
	t.Run("symlink target", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Skipf("cannot create a symlink on this host: %v", err)
		}
		if _, err := NewWriter(link, WriterOptions{Kind: KindCapture}); !errors.Is(err, ErrUnsafeTarget) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestReadBundle(t *testing.T) {
	dir, m := newCapture(t, t.TempDir(), "cap", threeProbes...)
	b, err := ReadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.ContentDigest != m.ContentDigest || b.Capture == nil || b.State == nil {
		t.Fatalf("bundle = %+v", b)
	}
	if b.Capture.Completeness.Status != CompletenessComplete {
		t.Fatalf("completeness = %+v", b.Capture.Completeness)
	}
	if !reflect.DeepEqual(b.State.Artifacts, sampleArtifacts()) {
		t.Fatal("state/device.json did not round-trip")
	}
	results, err := b.ReadProbeResults()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || results[0].ProbeID != "common.identity" || results[2].ProbeID != "common.zthird" {
		t.Fatalf("probe results = %+v", results)
	}
	// A change after verification is caught on read.
	writeRaw(t, dir, StateDeviceFile, []byte("{}\n"))
	if _, err := b.ReadFile(StateDeviceFile); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("read after tamper = %v", err)
	}
	if _, err := b.ReadFile("not/listed.json"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("read of an unlisted file = %v", err)
	}
	if _, err := ReadBundle(dir); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("ReadBundle of a tampered bundle = %v", err)
	}
}

// TestReadBundleRecomputesCompleteness builds a bundle by hand whose
// integrity is intact but whose capture.json claims "complete" next to a
// permission_denied probe (SPEC-0466 TF01-AC6).
func TestReadBundleRecomputesCompleteness(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cap")
	r := sampleProbeResult("common.identity", StatusPermissionDenied)
	doc := sampleCaptureDoc([]string{"common.identity"}, []ProbeResult{r})
	doc.Completeness = Completeness{Status: CompletenessComplete, Required: []string{"common.identity"}, Gaps: []CompletenessGap{}}
	b, err := MarshalFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, CaptureFile, b)
	m, err := BuildManifest(dir, testHeader(KindCapture))
	if err != nil {
		t.Fatal(err)
	}
	mb, err := MarshalFile(m)
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, ManifestFile, mb)
	if res := VerifyDir(dir); !res.OK {
		t.Fatalf("hand-built bundle should pass integrity: %s", describeFailures(res))
	}
	if _, err := ReadBundle(dir); !errors.Is(err, ErrCompletenessMismatch) {
		t.Fatalf("ReadBundle = %v, want ErrCompletenessMismatch", err)
	}
}

// TestReadBundleChecksCaptureConsistency: capture.json, probes/*.json and
// state/device.json of one bundle must tell the same story (SPEC-0466
// TF01-AC6, section 5.6). Each case keeps integrity intact by rebuilding the manifest,
// the way a forger with write access would; ReadBundle must still refuse.
func TestReadBundleChecksCaptureConsistency(t *testing.T) {
	// rewrite replaces rel (or removes it for nil) and rebuilds the manifest.
	rewrite := func(t *testing.T, dir string, files map[string][]byte) {
		t.Helper()
		for rel, b := range files {
			full := filepath.Join(dir, filepath.FromSlash(rel))
			if b == nil {
				if err := os.Remove(full); err != nil {
					t.Fatal(err)
				}
				continue
			}
			writeRaw(t, dir, rel, b)
		}
		if err := os.Remove(filepath.Join(dir, ManifestFile)); err != nil {
			t.Fatal(err)
		}
		m, err := BuildManifest(dir, testHeader(KindCapture))
		if err != nil {
			t.Fatal(err)
		}
		mb, err := MarshalFile(m)
		if err != nil {
			t.Fatal(err)
		}
		writeRaw(t, dir, ManifestFile, mb)
		if res := VerifyDir(dir); !res.OK {
			t.Fatalf("forged bundle should pass integrity: %s", describeFailures(res))
		}
	}
	marshal := func(t *testing.T, v any) []byte {
		t.Helper()
		b, err := MarshalFile(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name  string
		forge func(t *testing.T, dir string) map[string][]byte
	}{
		{"result permission_denied, summary captured", func(t *testing.T, dir string) map[string][]byte {
			r := sampleProbeResult("common.second", StatusPermissionDenied)
			return map[string][]byte{"probes/common.second.json": marshal(t, r)}
		}},
		{"result reason differs from summary", func(t *testing.T, dir string) map[string][]byte {
			r := sampleProbeResult("common.second", StatusCaptured)
			r.Reason = "something else"
			return map[string][]byte{"probes/common.second.json": marshal(t, r)}
		}},
		{"result file without summary", func(t *testing.T, dir string) map[string][]byte {
			return map[string][]byte{"probes/common.extra.json": marshal(t, sampleProbeResult("common.extra", StatusFailed))}
		}},
		{"summary without result file", func(t *testing.T, dir string) map[string][]byte {
			return map[string][]byte{"probes/common.zthird.json": nil}
		}},
		{"state carries an artifact no result reports", func(t *testing.T, dir string) map[string][]byte {
			arts := append(sampleArtifacts(), Artifact{
				ID: "project/git/abc", Type: "git", Scope: "project", Source: "common.identity", State: StateObserved,
				Provenance: Provenance{Method: "file", Confidence: ConfidenceProven, ObservedAt: FormatTime(testTime)}, Sensitivity: SensitivityPublic,
			})
			SortArtifacts(arts)
			return map[string][]byte{StateDeviceFile: marshal(t, StateDoc{Artifacts: arts})}
		}},
		{"state misses an artifact a result reports", func(t *testing.T, dir string) map[string][]byte {
			return map[string][]byte{StateDeviceFile: marshal(t, StateDoc{Artifacts: sampleArtifacts()[:1]})}
		}},
		{"evidence reference without a manifested file", func(t *testing.T, dir string) map[string][]byte {
			r := sampleProbeResult("common.second", StatusCaptured)
			r.RawEvidence = append(r.RawEvidence, EvidenceRef{Path: "evidence/common.second/gone", Size: 1, SHA256: SHA256Hex([]byte("x"))})
			return map[string][]byte{"probes/common.second.json": marshal(t, r)}
		}},
		{"evidence reference with another digest", func(t *testing.T, dir string) map[string][]byte {
			r := sampleProbeResult("common.second", StatusCaptured)
			r.RawEvidence[0].SHA256 = SHA256Hex([]byte("other"))
			return map[string][]byte{"probes/common.second.json": marshal(t, r)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := newCapture(t, t.TempDir(), "cap", threeProbes...)
			if _, err := ReadBundle(dir); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			rewrite(t, dir, tc.forge(t, dir))
			if _, err := ReadBundle(dir); !errors.Is(err, ErrInconsistentCapture) {
				t.Fatalf("ReadBundle = %v, want ErrInconsistentCapture", err)
			}
		})
	}
}

func TestReadSignatureFile(t *testing.T) {
	parent := t.TempDir()
	capDir, capM := newCapture(t, parent, "cap", "common.identity")
	base := filepath.Join(parent, "base")
	bm := newBaseline(t, capDir, capM, base)
	got, err := ReadSignatureFile(base)
	if err != nil {
		t.Fatal(err)
	}
	want, err := MarshalFile(testSignature{SchemaVersion: SchemaSignature, ContentDigest: bm.ContentDigest})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("signature bytes = %s, want %s", got, want)
	}
	if _, err := ReadSignatureFile(capDir); err == nil {
		t.Fatal("a capture has no signature file")
	}
	sig := filepath.Join(base, filepath.FromSlash(SignatureFile))
	outside := filepath.Join(t.TempDir(), "sig.json")
	if err := os.WriteFile(outside, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sig); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, sig); err != nil {
		t.Skipf("cannot create a symlink on this host: %v", err)
	}
	if _, err := ReadSignatureFile(base); err == nil {
		t.Fatal("a symlinked signature file must not be read")
	}
}

func TestBuildManifestRejectsBadTrees(t *testing.T) {
	h := testHeader(KindCapture)
	t.Run("bad name", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "a b.json", []byte("{}"))
		if _, err := BuildManifest(dir, h); !errors.Is(err, ErrBundleContent) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, "a.json", []byte("{}"))
		if err := os.Symlink(filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")); err != nil {
			t.Skipf("cannot create a symlink on this host: %v", err)
		}
		if _, err := BuildManifest(dir, h); !errors.Is(err, ErrBundleContent) {
			t.Fatalf("got %v", err)
		}
	})
	// SPEC-0470 section 4.4 step 3: signatures/ holds only the unlisted
	// signature file, so nothing under it can be manifested.
	t.Run("file under signatures", func(t *testing.T) {
		for _, kind := range []Kind{KindCapture, KindBaseline, KindDiff} {
			dir := t.TempDir()
			writeRaw(t, dir, CaptureFile, []byte("{}"))
			writeRaw(t, dir, "signatures/manifest.ed25519.json.bak", []byte("{}"))
			if _, err := BuildManifest(dir, testHeader(kind)); !errors.Is(err, ErrBundleContent) {
				t.Fatalf("%s: got %v, want ErrBundleContent", kind, err)
			}
			// The signature file itself is skipped, not refused.
			if err := os.Remove(filepath.Join(dir, "signatures", "manifest.ed25519.json.bak")); err != nil {
				t.Fatal(err)
			}
			writeRaw(t, dir, SignatureFile, []byte("{}"))
			if _, err := BuildManifest(dir, testHeader(kind)); err != nil {
				t.Fatalf("%s: signature file refused: %v", kind, err)
			}
		}
	})
	t.Run("header checks", func(t *testing.T) {
		dir := t.TempDir()
		for name, mut := range map[string]func(*ManifestHeader){
			"kind":       func(x *ManifestHeader) { x.Kind = "x" },
			"bundle id":  func(x *ManifestHeader) { x.BundleID = " " },
			"created at": func(x *ManifestHeader) { x.CreatedAt = time.Time{} },
			"subject":    func(x *ManifestHeader) { x.Subject = Subject{} },
		} {
			hh := h
			mut(&hh)
			if _, err := BuildManifest(dir, hh); err == nil {
				t.Errorf("header with bad %s accepted", name)
			}
		}
	})
}
