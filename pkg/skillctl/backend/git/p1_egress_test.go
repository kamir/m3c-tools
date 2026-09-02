package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// TestGitPlaintextCredRefused — CD-T8 / WIN-T10 (closes CD-03 HIGH + WIN-12): a
// write token must never ride cleartext HTTP to a non-loopback host, because
// base64(user:token) in an Authorization header is encoding, not encryption — an
// on-path attacker on a public network would capture a write-scoped registry
// token. Mirrors the OCI backend's TestOCIPlaintextCredRefused. The token IS
// attached over https:// (TLS protects it) and over http:// to a
// loopback/RFC1918 host (LAN/test registry), and REFUSED over http:// to a public
// host.
func TestGitPlaintextCredRefused(t *testing.T) {
	creds := fakeCreds{user: "deployer", token: "s3cret"}

	// (1) https:// (M3C_GIT_HTTP unset) to a PUBLIC host → token attached; TLS
	// protects the header. This is the normal production path.
	b, err := openGitLab("gitlab://gitlab.example.com/grp/skills", artifact.OpenOptions{Creds: creds})
	if err != nil {
		t.Fatalf("https to a public host must succeed: %v", err)
	}
	if b.(*gitBackend).token == "" {
		t.Error("https to a public host: the write token should be attached")
	}

	// Flip to plain HTTP for the LAN/test paths (M3C_GIT_HTTP=1 is the ONLY way
	// b.remote becomes http://).
	t.Setenv("M3C_GIT_HTTP", "1")

	// (2) http:// to loopback → token attached (a local dev/test registry).
	b, err = openGitLab("gitlab://127.0.0.1:8929/grp/skills", artifact.OpenOptions{Creds: creds})
	if err != nil {
		t.Fatalf("plain HTTP to loopback should be allowed: %v", err)
	}
	if b.(*gitBackend).token == "" {
		t.Error("plain HTTP to loopback: the write token should be attached")
	}

	// (3) http:// to an RFC1918 private host → token attached (LAN registry).
	if _, err := openGitLab("gitlab://192.168.0.131:8929/grp/skills", artifact.OpenOptions{Creds: creds}); err != nil {
		t.Errorf("plain HTTP to an RFC1918 host should be allowed: %v", err)
	}

	// (4) http:// to a PUBLIC host → REFUSED (this is the CD-03 HIGH). The bare
	// hostname is not provably local, so the credential is never attached.
	if b, err := openGitLab("gitlab://gitlab.example.com/grp/skills", artifact.OpenOptions{Creds: creds}); err == nil {
		t.Errorf("token over plain HTTP to a public host must be refused; got backend with token=%q", b.(*gitBackend).token)
	}
}

// TestReadCappedBounded — IS-T10 (IS-09 OOM DoS): a git clone is untrusted, so a
// hostile repo could commit a multi-GiB blob/event/bundle. readCapped mirrors the
// OCI fetchCapped bound: an under-cap file reads back exactly, an over-cap file
// returns a bounded-read ERROR (never a truncated success, never an OOM), and a
// file exactly at the cap is allowed.
func TestReadCappedBounded(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "small.json")
	if err := os.WriteFile(small, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readCapped(small, maxGitManifestBytes); err != nil || string(got) != `{"ok":true}` {
		t.Fatalf("readCapped(small) = %q, %v; want the file back verbatim", got, err)
	}

	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	// Over a 512-byte cap → error, and no more than cap+1 bytes are ever read.
	if _, err := readCapped(big, 512); err == nil {
		t.Fatal("readCapped over a 512-byte cap on a 1024-byte file must return a bounded-read error")
	}
	// Exactly at the cap is fine.
	if got, err := readCapped(big, 1024); err != nil || len(got) != 1024 {
		t.Fatalf("readCapped(big, 1024) = %d bytes, %v; want 1024 bytes, no error", len(got), err)
	}
}
