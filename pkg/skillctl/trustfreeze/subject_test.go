package trustfreeze

import (
	"strings"
	"testing"
)

// TestSubjectIDVector pins the SubjectID contract against values computed outside Go
// (shasum over the documented preimage).
func TestSubjectIDVector(t *testing.T) {
	cases := []struct{ os, host, want string }{
		{"linux", "host-a.example", "device/eb9aa81eeaaf3ce7"},
		{"linux", "HOST-A.Example", "device/eb9aa81eeaaf3ce7"},
		{"darwin", "host-a.example", "device/e7f05555771084e3"},
	}
	for _, tc := range cases {
		if got := SubjectID(tc.os, tc.host); got != tc.want {
			t.Errorf("SubjectID(%q, %q) = %q, want %q", tc.os, tc.host, got, tc.want)
		}
	}
}

func TestSubjectIDSeparation(t *testing.T) {
	a := SubjectID("linux", "host-a.example")
	for _, other := range [][2]string{
		{"windows", "host-a.example"},
		{"linux", "host-b.example"},
		{"linu", "xhost-a.example"},
		{"linux\x00host-a.example", ""},
	} {
		if SubjectID(other[0], other[1]) == a {
			t.Errorf("SubjectID(%q, %q) collides with the linux host-a id", other[0], other[1])
		}
	}
	if !strings.HasPrefix(a, "device/") || len(a) != len("device/")+16 {
		t.Fatalf("SubjectID shape = %q", a)
	}
}

func TestBundleID(t *testing.T) {
	got := BundleID(KindCapture, testTime, "device/eb9aa81eeaaf3ce7")
	if want := "tf-capture-20260102T030405.000000000Z-device-eb9aa81eeaaf3ce7"; got != want {
		t.Fatalf("BundleID = %q, want %q", got, want)
	}
}
