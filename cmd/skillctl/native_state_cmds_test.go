package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type qaNativeSourceCLI struct {
	base     *nativeCLIQAProfile
	doc      map[string]any
	server   *httptest.Server
	requests atomic.Int32
	mu       sync.Mutex
	response []byte
	status   int
	location string
}

func qaNativeSourceCLIProof(t *testing.T, key ed25519.PrivateKey, epoch int, issued time.Time) []byte {
	t.Helper()
	head, err := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: epoch, IssuedAt: issued, Digests: []string{}, Emergency: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.SignEnvelopeSignature(key, head); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func qaNativeSourceCLITLS(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "CLI source fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(12), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}}, NextProtos: []string{"http/1.1"}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
func qaNativeSourceCLIFixture(t *testing.T) *qaNativeSourceCLI {
	t.Helper()
	f := &qaNativeSourceCLI{base: nativeCLIQAProfileFixture(t), status: http.StatusOK}
	raw, err := os.ReadFile(f.base.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &f.doc); err != nil {
		t.Fatal(err)
	}
	reviewer, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]ed25519.PrivateKey{"artifact_trust": f.base.artifactKey, "revocation_trust": f.base.revocationKey} {
		roots := []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + "\ngovernance_minimum: green\ngovernance_quorum: 1\nsigners:\n - reviewer_id: source-reviewer\n   pubkey_b64: " + base64.StdEncoding.EncodeToString(reviewer) + "\n")
		old := f.doc["native"].(map[string]any)[name].(map[string]any)
		path := old["path"].(string)
		if err = os.WriteFile(path, roots, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(roots)
		old["sha256"] = hex.EncodeToString(sum[:])
	}
	f.server, raw = qaNativeSourceCLITLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.RequestURI() != "/explicit/full-evidence" || r.Method != http.MethodGet || r.ProtoMajor != 1 || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-API-Key") != "" {
			t.Error("unexpected source route, protocol or private authentication")
		}
		f.mu.Lock()
		body := append([]byte(nil), f.response...)
		status := f.status
		location := f.location
		f.mu.Unlock()
		if body == nil {
			body = qaNativeSourceCLIProof(t, f.base.revocationKey, 2, time.Now().UTC())
		}
		w.Header().Set("Content-Type", "application/json")
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
		if _, e := w.Write(body); e != nil {
			t.Error(e)
		}
	}))
	caPath := filepath.Join(f.base.project, "source-ca.pem")
	if err = os.WriteFile(caPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	f.doc["schema"] = "m3c.enterprise-project-profile/v3"
	f.doc["native"].(map[string]any)["revocation_source"] = map[string]any{"kind": "https-native-evidence", "url": f.server.URL + "/explicit/full-evidence", "auth": "none", "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]any{"path": caPath, "sha256": hex.EncodeToString(sum[:])}}}
	f.save(t)
	return f
}
func (f *qaNativeSourceCLI) save(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.base.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	f.base.pin = hex.EncodeToString(sum[:])
	if _, err = projectpolicy.LoadNativePinned(f.base.path, f.base.pin, f.base.project, f.base.home); err != nil {
		t.Fatal("actual selected TLS/source fixture invalid", err)
	}
}
func (f *qaNativeSourceCLI) journal(t *testing.T) *registry.NativeJournal {
	t.Helper()
	p, err := projectpolicy.LoadNativePinned(f.base.path, f.base.pin, f.base.project, f.base.home)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.OfflineInstallSelection()
	if err != nil {
		t.Fatal(err)
	}
	j, err := registry.OpenNativeJournal(s)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func (f *qaNativeSourceCLI) args() []string {
	return []string{"trust", "native-state", "adopt", "--enterprise-profile", f.base.path, "--enterprise-profile-sha256", f.base.pin, "--home", f.base.home, "--json"}
}

func qaNativeSourceEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, key+"=") {
			out = append(out, entry)
		}
	}
	return append(out, key+"="+value)
}

// GOFLAGS uses cmd/internal/quoted whole-field quoting without escape expansion.
func qaNativeSourceFlagWords(t *testing.T, text string) []string {
	t.Helper()
	var out []string
	for text != "" {
		text = strings.TrimLeft(text, " \t\r\n")
		if text == "" {
			break
		}
		if text[0] == '\'' || text[0] == '"' {
			q := text[0]
			text = text[1:]
			n := strings.IndexByte(text, q)
			if n < 0 {
				t.Fatal("unterminated inherited GOFLAGS field")
			}
			out = append(out, text[:n])
			text = text[n+1:]
		} else {
			n := strings.IndexAny(text, " \t\r\n")
			if n < 0 {
				out = append(out, text)
				break
			}
			out = append(out, text[:n])
			text = text[n:]
		}
	}
	return out
}
func qaNativeSourceQuoteFlag(t *testing.T, arg string) string {
	t.Helper()
	if !strings.ContainsAny(arg, " \t\r\n\"'") {
		return arg
	}
	if !strings.Contains(arg, "'") {
		return "'" + arg + "'"
	}
	if !strings.Contains(arg, "\"") {
		return "\"" + arg + "\""
	}
	t.Fatal("unrepresentable private fixture flag")
	return ""
}
func qaNativeSourceStartsWithPanic(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) == 0 {
		return false
	}
	stmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	name, ok := call.Fun.(*ast.Ident)
	if !ok || name.Name != "panic" || len(call.Args) != 1 {
		return false
	}
	_, ok = call.Args[0].(*ast.BasicLit)
	return ok
}

// qaNativeSourceBinary never depends on the process-local TestMain mock. Each
// target provider keeps its upstream initializer and has four panic methods.
func qaNativeSourceBinary(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := func(args ...string) []byte {
		t.Helper()
		t.Logf("isolated fixture Go command: %q", args)
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.WaitDelay = time.Second
		cmd.Dir = root
		cmd.Env = os.Environ()
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated fixture Go command failed: %v\n%s", e, out)
		}
		return out
	}
	cache := strings.TrimSpace(string(command("env", "GOMODCACHE")))
	var module struct{ Version string }
	if err = json.Unmarshal(command("list", "-m", "-json", "github.com/zalando/go-keyring"), &module); err != nil {
		t.Fatal(err)
	}
	if module.Version != "v0.2.8" {
		t.Fatal("review provider fixture when upstream dependency changes")
	}
	original := filepath.Join(cache, "github.com", "zalando", "go-keyring@"+module.Version)
	replacement := filepath.Join(dir, "keyring")
	if err = os.Mkdir(replacement, 0700); err != nil {
		t.Fatal(err)
	}
	originals := map[string]string{}
	for _, name := range []string{"go.mod", "go.sum", "LICENSE", "keyring.go", "keyring_mock.go", "keyring_fallback.go", "keyring_darwin.go", "keyring_unix.go", "keyring_windows.go"} {
		raw, e := os.ReadFile(filepath.Join(original, name))
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		originals[name] = hex.EncodeToString(sum[:])
		if strings.HasSuffix(name, "_darwin.go") || strings.HasSuffix(name, "_unix.go") || strings.HasSuffix(name, "_windows.go") {
			text := string(raw)
			start := strings.Index(text, "package keyring")
			init := strings.LastIndex(text, "func init() {")
			if start < 0 || init < 0 {
				t.Fatal("upstream provider layout changed")
			}
			typ := map[string]string{"keyring_darwin.go": "macOSXKeychain", "keyring_unix.go": "secretServiceProvider", "keyring_windows.go": "windowsKeychain"}[name]
			text = text[:start] + "package keyring\n\ntype " + typ + " struct{}\n\n" + text[init:] + "\n"
			for _, method := range []struct{ name, args, result string }{{"Get", "string,string", "(string,error)"}, {"Set", "string,string,string", "error"}, {"Delete", "string,string", "error"}, {"DeleteAll", "string", "error"}} {
				text += "func (" + typ + ") " + method.name + "(" + method.args + ") " + method.result + " { panic(\"native source fixture provider trap: " + method.name + "\") }\n"
			}
			raw = []byte(text)
		}
		if e = os.WriteFile(filepath.Join(replacement, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	trapStateSource := `package keyring
import("reflect";"runtime")
func NativeProviderTrapActive() bool {
 expected := map[string]string{"darwin":"keyring.macOSXKeychain","linux":"keyring.secretServiceProvider","windows":"keyring.windowsKeychain"}[runtime.GOOS]
 actual:=reflect.TypeOf(provider)
 return expected!="" && actual!=nil && actual.String()==expected
}
`
	if err = os.WriteFile(filepath.Join(replacement, "native_source_fixture.go"), []byte(trapStateSource), 0600); err != nil {
		t.Fatal(err)
	}
	receipt, err := json.Marshal(originals)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "provider-originals.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(dir, "trap.mod")
	for _, name := range []string{"go.mod", "go.sum"} {
		raw, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		target := mod
		if name == "go.sum" {
			target = filepath.Join(dir, "trap.sum")
		}
		if e = os.WriteFile(target, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}

	directFiles := map[string][]string{
		"pkg/er1/config.go":                          {"keychainAPIKey"},
		"pkg/skillctl/artifactauth/creds.go":         {"keychain"},
		"pkg/skillctl/artifactauth/store_darwin.go":  {"platformStore", "platformDelete"},
		"pkg/skillctl/artifactauth/store_windows.go": {"platformStore", "platformDelete"},
		"pkg/skillctl/artifactauth/creds_windows.go": {"osCredStore", "StoreCred", "DeleteCred", "dpapiProtect", "dpapiUnprotect"},
	}
	replacements := map[string]string{}
	for _, word := range qaNativeSourceFlagWords(t, os.Getenv("GOFLAGS")) {
		if strings.HasPrefix(word, "-overlay=") {
			path := strings.TrimPrefix(word, "-overlay=")
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var inherited struct{ Replace map[string]string }
			if e = json.Unmarshal(raw, &inherited); e != nil {
				t.Fatal(e)
			}
			for original, target := range inherited.Replace {
				replacements[original] = target
			}
		}
	}

	for relative, names := range directFiles {
		path := filepath.Join(root, relative)
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		originals[relative] = hex.EncodeToString(sum[:])
		inheritedTarget, inherited := replacements[path]
		if inherited {
			raw, e = os.ReadFile(inheritedTarget)
			if e != nil {
				t.Fatal(e)
			}
		}
		fset := token.NewFileSet()
		file, e := parser.ParseFile(fset, path, raw, parser.ParseComments)
		if e != nil {
			t.Fatal(e)
		}
		found := map[string]bool{}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			for _, name := range names {
				if fn.Name.Name == name {
					found[name] = true
					if inherited {
						if !qaNativeSourceStartsWithPanic(fn) {
							t.Fatal("inherited direct-provider overlay collision is not an unconditional trap", relative, name)
						}
						continue
					}
					// Preserve the original unreachable body for compile-time references; the
					// unconditional first statement prevents every native call in this helper.
					stop := &ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent("panic"), Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("native source direct provider trap: " + relative + ":" + name)}}}}
					fn.Body.List = append([]ast.Stmt{stop}, fn.Body.List...)
				}
			}
		}
		if len(found) != len(names) {
			t.Fatal("review direct-provider harness after helper changes", relative)
		}
		if inherited {
			continue
		}
		var out bytes.Buffer
		if e = format.Node(&out, fset, file); e != nil {
			t.Fatal(e)
		}
		target := filepath.Join(dir, "direct", relative)
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(target, out.Bytes(), 0600); e != nil {
			t.Fatal(e)
		}
		replacements[path] = target
	}
	// Only the private fault-test build includes this test entrypoint. Product
	// builds ignore _test.go and keep their ordinary platform provider init.
	mockPath := filepath.Join(root, "cmd", "skillctl", "auth_mock_test.go")
	if _, collision := replacements[mockPath]; collision {
		t.Fatal("inherited TestMain overlay collision")
	}
	mockRaw, e := os.ReadFile(mockPath)
	if e != nil {
		t.Fatal(e)
	}
	mockSHA := sha256.Sum256(mockRaw)
	originals["cmd/skillctl/auth_mock_test.go"] = hex.EncodeToString(mockSHA[:])
	fset := token.NewFileSet()
	mockAST, e := parser.ParseFile(fset, mockPath, mockRaw, parser.ParseComments)
	if e != nil {
		t.Fatal(e)
	}
	changed := 0
	for _, decl := range mockAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestMain" || fn.Body == nil {
			continue
		}
		for i, stmt := range fn.Body.List {
			expr, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expr.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "keyring" || selector.Sel.Name != "MockInit" || len(call.Args) != 0 {
				continue
			}
			changed++
			check := &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("keyring"), Sel: ast.NewIdent("NativeProviderTrapActive")}}
			stop := &ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent("panic"), Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("native source fault helper lacks active private provider trap")}}}}
			fn.Body.List[i] = &ast.IfStmt{Cond: &ast.UnaryExpr{Op: token.NOT, X: check}, Body: &ast.BlockStmt{List: []ast.Stmt{stop}}}
		}
	}
	if changed != 1 {
		t.Fatal("expected exactly one private TestMain MockInit replacement", changed)
	}
	var mockOut bytes.Buffer
	if e = format.Node(&mockOut, fset, mockAST); e != nil {
		t.Fatal(e)
	}
	mockTarget := filepath.Join(dir, "fault-auth-mock_test.go")
	if e = os.WriteFile(mockTarget, mockOut.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	replacements[mockPath] = mockTarget
	overlay := filepath.Join(dir, "direct-overlay.json")
	overlayRaw, e := json.Marshal(map[string]any{"Replace": replacements})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(overlay, overlayRaw, 0600); e != nil {
		t.Fatal(e)
	}
	receipt, err = json.Marshal(originals)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "provider-originals.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	command("mod", "edit", "-modfile="+mod, "-replace=github.com/zalando/go-keyring="+replacement)
	binary := filepath.Join(dir, "skillctl")
	if os.PathSeparator == '\\' {
		binary += ".exe"
	}
	command("build", "-modfile="+mod, "-overlay="+overlay, "-o", binary, "./cmd/skillctl")
	helper := filepath.Join(dir, "skillctl-fault.test")
	if os.PathSeparator == '\\' {
		helper += ".exe"
	}
	command("test", "-c", "-modfile="+mod, "-overlay="+overlay, "-o", helper, "./cmd/skillctl")
	for _, artifact := range []string{binary, helper} {
		info, e := buildinfo.ReadFile(artifact)
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, dep := range info.Deps {
			if dep.Path == "github.com/zalando/go-keyring" && dep.Replace != nil && dep.Replace.Path == replacement {
				found = true
			}
		}
		if !found {
			t.Fatal("built artifact lacks private native-provider replacement", artifact)
		}
		data, e := os.ReadFile(artifact)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(data)
		t.Logf("isolated built artifact SHA256: %s %x", artifact, sum)
	}
	overlaySHA := sha256.Sum256(overlayRaw)
	t.Logf("composed source overlay SHA256: %x", overlaySHA)

	t.Logf("native source harness original SHA256 receipts: %s", receipt)
	return binary, strings.TrimSpace(os.Getenv("GOFLAGS") + " " + qaNativeSourceQuoteFlag(t, "-modfile="+mod) + " " + qaNativeSourceQuoteFlag(t, "-overlay="+overlay)), helper
}

func qaNativeSourceArtifactInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	all := nativeCLIQAInventory(t, root)
	out := map[string]string{}
	prefix := filepath.Join(".claude", "native-mutation-state")
	for path, value := range all {
		if path != prefix && !strings.HasPrefix(path, prefix+string(os.PathSeparator)) {
			out[path] = value
		}
	}
	return out
}

func qaNativeSourceRun(t *testing.T, binary, flags string, f *qaNativeSourceCLI, args []string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = time.Second
	cmd.Dir = f.base.project
	cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.base.home), "GOFLAGS", flags)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("source CLI exceeded bounded execution", ctx.Err())
	}
	var exit *exec.ExitError
	if err == nil {
		return 0, string(out)
	}
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	t.Fatal(err)
	return -1, ""
}

type qaNativeSourceFailedWriter struct{ short bool }

func (w qaNativeSourceFailedWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("synthetic selected output fault")
}

func TestTrustNativeEvidenceAdoptActualCLI(t *testing.T) {
	if mode := os.Getenv("M3C_NATIVE_SOURCE_OUTPUT_CHILD"); mode != "" {
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv("M3C_NATIVE_SOURCE_OUTPUT_ARGS")), &args); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		if code := runTrustNativeState(args, qaNativeSourceFailedWriter{short: mode == "short"}, &stderr); code != 1 || !strings.Contains(stderr.String(), "may already be updated") {
			t.Fatalf("output failure claimed success or rollback: %d %s", code, stderr.String())
		}
		return
	}
	binary, flags, faultChild := qaNativeSourceBinary(t)
	t.Run("real-pinned-TLS-stale-history-update-only", func(t *testing.T) {
		f := qaNativeSourceCLIFixture(t)
		f.doc["native"].(map[string]any)["revocation_policy"].(map[string]any)["max_age_seconds"] = 1
		f.save(t)
		j := f.journal(t)
		issued := time.Now().UTC()
		if _, err := j.Enroll(context.Background(), qaNativeSourceCLIProof(t, f.base.revocationKey, 1, issued)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(issued.Add(1100 * time.Millisecond)))
		before := qaNativeSourceArtifactInventory(t, f.base.home)
		code, out := qaNativeSourceRun(t, binary, flags, f, f.args())
		if code != 0 {
			t.Fatalf("actual pinned TLS update refused: %d %s", code, out)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal("actual CLI status is not JSON", err)
		}
		if len(got) != 5 || got["epoch"] != float64(2) || got["history_authority_id"] == "" || got["evidence_sha256"] == "" {
			t.Fatal("CLI returned unbound status or grant", out)
		}
		status, err := j.Status(context.Background())
		if err != nil || status.Epoch != 2 || status.HistoryAuthorityID != got["history_authority_id"] || status.EvidenceDigest != got["evidence_sha256"] {
			t.Fatal("actual subprocess did not update real journal", err)
		}
		if !reflect.DeepEqual(before, qaNativeSourceArtifactInventory(t, f.base.home)) {
			t.Fatal("adoption changed installed artifact inventory")
		}
		if f.requests.Load() != 1 || f.base.requests.Load() != 0 {
			t.Fatal("unexpected source/carrier request count")
		}
	})
	for _, name := range []string{"missing-history", "v2-offline", "wrong-key", "bad-pin", "foreign-home", "source-non200", "unknown-flag", "pin-without-profile", "empty-pin", "empty-home", "relative-profile", "wrong-CA", "foreign-redirect"} {
		t.Run(name, func(t *testing.T) {
			f := qaNativeSourceCLIFixture(t)
			args := f.args()
			want := 12
			requests := int32(0)
			var redirected atomic.Int32
			if name != "missing-history" && name != "pin-without-profile" {
				if _, err := f.journal(t).Enroll(context.Background(), qaNativeSourceCLIProof(t, f.base.revocationKey, 1, time.Now().UTC().Add(-time.Minute))); err != nil {
					t.Fatal(err)
				}
			}
			f.mu.Lock()
			switch name {
			case "missing-history":
				want = 22
			case "v2-offline":
				f.doc["schema"] = projectpolicy.NativeSchema
				delete(f.doc["native"].(map[string]any), "revocation_source")
				f.save(t)
				args = f.args()
			case "wrong-key":
				f.response = qaNativeSourceCLIProof(t, f.base.artifactKey, 2, time.Now().UTC())
				requests = 1
			case "bad-pin":
				args[6] = strings.Repeat("0", 64)
			case "foreign-home":
				args[8] = t.TempDir()
			case "empty-pin":
				args[6] = ""
			case "empty-home":
				args[8] = ""
			case "relative-profile":
				args[4] = "source-profile.json"
			case "wrong-CA":
				_, ca := qaNativeSourceCLITLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unselected CA endpoint contacted") }))
				source := f.doc["native"].(map[string]any)["revocation_source"].(map[string]any)
				ref := source["tls"].(map[string]any)["ca"].(map[string]any)
				if err := os.WriteFile(ref["path"].(string), ca, 0600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(ca)
				ref["sha256"] = hex.EncodeToString(sum[:])
				f.save(t)
				args = f.args()
				want = 1
			case "foreign-redirect":
				other, _ := qaNativeSourceCLITLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
				f.location = other.URL + "/forbidden"
				f.status = http.StatusFound
				want = 1
				requests = 1
			case "source-non200":
				f.status = 503
				want = 1
				requests = 1
			case "unknown-flag":
				args = append(args, "--force")
				want = 2
			case "pin-without-profile":
				args = []string{"trust", "native-state", "adopt", "--enterprise-profile-sha256", f.base.pin}
				want = 2
			}
			f.mu.Unlock()
			before := nativeCLIQAInventory(t, f.base.home)
			code, out := qaNativeSourceRun(t, binary, flags, f, args)
			if code != want {
				t.Fatalf("%s exact exit: got%d want%d %s", name, code, want, out)
			}
			if f.requests.Load() != requests || f.base.requests.Load() != 0 || redirected.Load() != 0 || !reflect.DeepEqual(before, nativeCLIQAInventory(t, f.base.home)) {
				t.Fatal("refusal fetched incorrectly or changed retained state")
			}
		})
	}
	for _, mode := range []string{"error", "short"} {
		t.Run("writer-"+mode+"-after-update", func(t *testing.T) {
			f := qaNativeSourceCLIFixture(t)
			j := f.journal(t)
			if _, err := j.Enroll(context.Background(), qaNativeSourceCLIProof(t, f.base.revocationKey, 1, time.Now().UTC().Add(-time.Minute))); err != nil {
				t.Fatal(err)
			}
			args, err := json.Marshal(f.args()[2:])
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, faultChild, "-test.run=^TestTrustNativeEvidenceAdoptActualCLI$")
			cmd.WaitDelay = time.Second
			cmd.Dir = f.base.project
			env := qaNativeSourceEnv(nativeCLIQAEnv(f.base.home), "GOFLAGS", flags)
			env = qaNativeSourceEnv(env, "M3C_NATIVE_SOURCE_OUTPUT_CHILD", mode)
			cmd.Env = qaNativeSourceEnv(env, "M3C_NATIVE_SOURCE_OUTPUT_ARGS", string(args))
			out, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil {
				t.Fatalf("real runner output fault child failed: %v %s", err, out)
			}
			status, err := j.Status(context.Background())
			if err != nil || status.Epoch != 2 {
				t.Fatal("writer fault was not after actual update", err)
			}
		})
	}
}
