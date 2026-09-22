package capture

import (
	"bytes"
	"path"
	"testing"
)

// TestBuiltinProfilesHaveNoCR: a profile digest is taken over the embedded
// bytes, so a CRLF checkout would record a different digest for the same
// built-in profile on Windows than on Linux. .gitattributes pins the files
// to LF; this catches a checkout or an edit that ignored it.
func TestBuiltinProfilesHaveNoCR(t *testing.T) {
	ids := BuiltinProfileIDs()
	if len(ids) == 0 {
		t.Fatal("no built-in profiles")
	}
	for _, id := range ids {
		b, err := builtinProfiles.ReadFile(path.Join("profiles", id+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(b, '\r') >= 0 {
			t.Errorf("profile %s contains a CR byte", id)
		}
	}
}
