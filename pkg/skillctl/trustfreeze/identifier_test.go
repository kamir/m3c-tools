package trustfreeze

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// SPEC-0470 section 4.2: reviewer, change and actor ids are 1 to 128 ASCII
// letters, digits and . _ - @ + :
func TestValidateIdentifier(t *testing.T) {
	for _, ok := range []string{"a", "alice", "id:alice@example", "CHG-0001", "a.b_c-d@e+f:g", "Z9", strings.Repeat("x", MaxIdentifierLen)} {
		if err := ValidateIdentifier(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " ", "a b", "a/b", `a\b`, "a=b", "a;b", "a,b", "#1", "(a)", "a\tb", "a\nb", "\u00e4", "a\u200b", strings.Repeat("x", MaxIdentifierLen+1)} {
		if err := ValidateIdentifier(bad); !errors.Is(err, ErrInvalidIdentifier) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

// SPEC-0469 section 4.2: the gap reasons are a closed, sorted list that
// includes the diff-only cause not_applicable.
func TestGapReasons(t *testing.T) {
	got := GapReasons()
	if !slices.IsSorted(got) || len(got) != 6 || !slices.Contains(got, GapNotApplicable) || !slices.Contains(got, GapNotCaptured) {
		t.Fatalf("GapReasons = %q", got)
	}
	got[0] = "mutated"
	if GapReasons()[0] == "mutated" {
		t.Fatal("GapReasons shares its backing array")
	}
}

// SPEC-0470 section 4.4: the capture manifest rebuilt from a baseline equals
// the capture's own manifest, and every input of the pinned derivation
// matters.
func TestDeriveCaptureManifest(t *testing.T) {
	capDir, capM := newCapture(t, t.TempDir(), "capture", "common.identity")
	b, err := ReadBundle(capDir)
	if err != nil {
		t.Fatal(err)
	}
	// The core fixture writes created_at = testTime; the engine's derivation
	// uses capture.json finished_at, so rebuild the fixture's header that way.
	finished, err := ParseTime(b.Capture.Capture.FinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	want := capM
	want.CreatedAt = FormatTime(finished)
	want.BundleID = BundleID(KindCapture, finished, capM.Subject.ID)
	if want.ContentDigest, err = ComputeContentDigest(want); err != nil {
		t.Fatal(err)
	}

	baseline := capM
	baseline.Kind = KindBaseline
	baseline.Files = append(slices.Clone(capM.Files), FileEntry{Path: ApprovalFile, Size: 3, SHA256: strings.Repeat("a", 64)})
	slices.SortFunc(baseline.Files, func(x, y FileEntry) int { return strings.Compare(x.Path, y.Path) })
	got, err := DeriveCaptureManifest(baseline, *b.Capture)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentDigest != want.ContentDigest || got.Kind != KindCapture || !got.BundlePolicy.RejectAdditions || slices.ContainsFunc(got.Files, func(f FileEntry) bool { return f.Path == ApprovalFile }) {
		t.Fatalf("derived %+v\nwant    %+v", got, want)
	}

	// Each input changes the digest: finished_at, subject and files.
	doc := *b.Capture
	doc.Capture.FinishedAt = FormatTime(finished.Add(time.Nanosecond))
	if d, _ := DeriveCaptureManifest(baseline, doc); d.ContentDigest == want.ContentDigest {
		t.Fatal("finished_at does not enter the derivation")
	}
	other := baseline
	other.Subject.ID = "device/0000000000000000"
	if d, _ := DeriveCaptureManifest(other, *b.Capture); d.ContentDigest == want.ContentDigest {
		t.Fatal("the subject does not enter the derivation")
	}
	fewer := baseline
	fewer.Files = slices.Clone(baseline.Files[:len(baseline.Files)-1])
	if fewer.Files[0].Path != ApprovalFile {
		t.Fatalf("fixture error: files %v", fewer.Files)
	}
	if d, _ := DeriveCaptureManifest(fewer, *b.Capture); d.ContentDigest == want.ContentDigest {
		t.Fatal("the file list does not enter the derivation")
	}
	for _, bad := range []string{"", "yesterday", FormatTime(time.Time{})} {
		doc := *b.Capture
		doc.Capture.FinishedAt = bad
		if _, err := DeriveCaptureManifest(baseline, doc); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("finished_at %q: err = %v", bad, err)
		}
	}
}
