package redact

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Synthetic secrets. None of them is a real credential.
const (
	opaque   = "s3cr3t-ZXCVBNM-0123456789"
	ghToken  = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	ghPAT    = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"
	awsKeyID = "AKIA" + "ABCDEFGHIJKLMNOP"
	slackTok = "xoxb-" + "123456789012-abcdefABCDEF"
	jwtTok   = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
	pemKey   = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nAAAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5\n-----END OPENSSH PRIVATE KEY-----"
)

func redactString(t *testing.T, r *Redactor, in string) (string, RedactionLog) {
	t.Helper()
	res, err := r.RedactBytes(context.Background(), EvidenceDescriptor{Name: "test"}, []byte(in))
	if err != nil {
		t.Fatalf("RedactBytes: %v", err)
	}
	return string(res.Data.Bytes()), res.Log
}

// TestRedactDefaultPatterns covers every default class of SPEC-0467 section 5.2
// (R5).
func TestRedactDefaultPatterns(t *testing.T) {
	cases := []struct {
		name, in, secret, class string
	}{
		{"pem", "key:\n" + pemKey + "\ntrailer\n", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", ClassPrivateKey},
		{"pem_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + opaque + "\n-----END RSA PRIVATE KEY-----\n", opaque, ClassPrivateKey},
		{"pem_truncated", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + opaque + "\n", opaque, ClassPrivateKey},
		{"bearer_header", "Authorization: Bearer " + opaque + "\n", opaque, ClassAuthorization},
		{"basic_header", "authorization: Basic " + opaque + "\n", opaque, ClassAuthorization},
		{"json_authorization", `{"Authorization": "Basic ` + opaque + `"}`, opaque, ClassAuthorization},
		{"bearer_free", "curl -H 'x: y' bearer " + opaque, opaque, ClassBearerToken},
		{"password_eq", "password=" + opaque + "\n", opaque, "password"},
		{"passwd_colon", "PASSWD: " + opaque + "\n", opaque, "password"},
		{"json_client_secret", `{"client_secret": "` + opaque + `", "x": 1}`, opaque, "client_secret"},
		{"api_key_spaced", "api key = " + opaque + "\n", opaque, "api_key"},
		{"flag_token", "--token=" + opaque, opaque, "token"},
		{"env_aws_secret", `export AWS_SECRET_ACCESS_KEY="` + opaque + `"`, opaque, "access_key"},
		{"refresh_token", "refresh-token: " + opaque, opaque, "refresh_token"},
		{"private_key_kv", "private_key='" + opaque + "'", opaque, "private_key"},
		{"session", "sessionid=" + opaque + "&next=/", opaque, "session"},
		{"cookie_header", "Cookie: a=" + opaque + "; b=2\n", opaque, ClassCookie},
		{"set_cookie", "Set-Cookie: sid=" + opaque + "; Path=/\n", opaque, ClassCookie},
		{"aws_key_id", "id " + awsKeyID + " end", awsKeyID, ClassAWSAccessKey},
		{"github_ghp", "remote " + ghToken + "\n", ghToken, ClassGitHubToken},
		{"github_pat", ghPAT, ghPAT, ClassGitHubToken},
		{"slack", "SLACK " + slackTok, slackTok, ClassSlackToken},
		{"jwt", "jwt " + jwtTok + " end", jwtTok, ClassJWT},
		{"url_credential", "origin https://alice:" + opaque + "@git.example/repo.git", opaque, ClassURLCredential},
		{"quoted_escape", `"password": "a\"` + opaque + `"`, opaque, "password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, log := redactString(t, Default(), tc.in)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret survived: %q", out)
			}
			if !strings.Contains(out, Marker(tc.class)) {
				t.Fatalf("want marker %s in %q (log %v)", Marker(tc.class), out, log)
			}
			if log[tc.class] == 0 {
				t.Fatalf("log %v has no %s entry", log, tc.class)
			}
		})
	}
}

// TestRedactKeepsIdentityOutput: the outputs the identity probe parses must
// pass unchanged, or the probe would lose its fields.
func TestRedactKeepsIdentityOutput(t *testing.T) {
	for _, in := range []string{
		"PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nHOME_URL=\"https://www.ubuntu.com/\"\nPRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n",
		"ProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n",
		"6.8.0-45-generic\n",
		"23.5.0\n",
		"host-a.example",
	} {
		out, log := redactString(t, Default(), in)
		if out != in || log.Total() != 0 {
			t.Errorf("changed benign output\n in: %q\nout: %q\nlog: %v", in, out, log)
		}
	}
}

// TestRedactIdempotent: a second pass changes nothing, so the engine's final
// pass over already redacted results is a no-op.
func TestRedactIdempotent(t *testing.T) {
	in := "password=" + opaque + "\nAuthorization: Bearer " + opaque + "\n" + ghToken + "\n" + `{"token": "` + opaque + `"}` + "\nCookie: a=b\n"
	once, _ := redactString(t, Default(), in)
	twice, log := redactString(t, Default(), once)
	if once != twice || log.Total() != 0 {
		t.Fatalf("second pass changed output\nonce:  %q\ntwice: %q\nlog: %v", once, twice, log)
	}
}

// TestRedactArgs covers a token as a separate argument after a sensitive
// flag, an inline flag value and a pattern-shaped positional (TF02-AC3).
func TestRedactArgs(t *testing.T) {
	args := []string{"--token", opaque, "--password=" + opaque, "-api-key", opaque, ghToken, "--verbose", "keep"}
	out, log, err := Default().RedactArgs(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(out, " ")
	if strings.Contains(joined, opaque) || strings.Contains(joined, ghToken) {
		t.Fatalf("secret survived in args: %q", out)
	}
	if out[0] != "--token" || out[6] != "--verbose" || out[7] != "keep" {
		t.Fatalf("non-secret arguments changed: %q", out)
	}
	if log.Total() != 4 {
		t.Fatalf("log total %d, want 4: %v", log.Total(), log)
	}
	if args[1] != opaque {
		t.Fatal("input slice was modified")
	}
}

// TestRedactValue: sensitive keys replace the whole value, strings are
// pattern-redacted, numbers keep their type (TF02-AC3, JSON values).
func TestRedactValue(t *testing.T) {
	var in any
	dec := json.NewDecoder(strings.NewReader(`{"name":"svc","count":12,"auth":{"client_secret":"` + opaque + `","nested":{"list":["ok","` + ghToken + `"]}},"password":{"a":1},"ratio":1.5}`))
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	out, log, err := Default().RedactValue(context.Background(), ValueContext{Path: "$"}, in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, opaque) || strings.Contains(s, ghToken) {
		t.Fatalf("secret survived: %s", s)
	}
	for _, want := range []string{`"count":12`, `"ratio":1.5`, `"password":"[REDACTED:password]"`, `"client_secret":"[REDACTED:client_secret]"`, `"name":"svc"`} {
		if !strings.Contains(s, want) {
			t.Errorf("want %s in %s", want, s)
		}
	}
	if log.Total() != 3 {
		t.Errorf("log total %d, want 3: %v", log.Total(), log)
	}
	if ms, _, err := Default().RedactValue(context.Background(), ValueContext{}, map[string]string{"api_token": opaque, "user": "alice"}); err != nil {
		t.Fatal(err)
	} else if m := ms.(map[string]string); m["api_token"] != Marker("token") || m["user"] != "alice" {
		t.Fatalf("map[string]string result %v", m)
	}
}

// TestRedactValueFailClosed: unknown types and key collisions are errors,
// never pass-through.
func TestRedactValueFailClosed(t *testing.T) {
	type custom struct{ Secret string }
	for name, v := range map[string]any{
		"struct":     custom{Secret: opaque},
		"pointer":    &custom{Secret: opaque},
		"collision":  map[string]any{ghToken: "a", "[REDACTED:github_token]": "b"},
		"stringer":   stringerValue(opaque),
		"deep_slice": []any{map[string]any{"x": custom{}}},
	} {
		out, _, err := Default().RedactValue(context.Background(), ValueContext{}, v)
		if !errors.Is(err, ErrRedactionFailed) || out != nil {
			t.Errorf("%s: got (%v, %v), want ErrRedactionFailed and no value", name, out, err)
		}
	}
}

type stringerValue string

func (s stringerValue) String() string { return string(s) }

// TestRedactFailClosed: a done context or oversized input yields an error
// and no data (SPEC-0467 R5, fail-closed).
func TestRedactFailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Default().RedactBytes(ctx, EvidenceDescriptor{Name: "x"}, []byte("password="+opaque))
	if !errors.Is(err, ErrRedactionFailed) || len(res.Data.Bytes()) != 0 {
		t.Fatalf("canceled: got %q, %v", res.Data.Bytes(), err)
	}
	small, err := New(WithMaxInputBytes(8))
	if err != nil {
		t.Fatal(err)
	}
	res, err = small.RedactBytes(context.Background(), EvidenceDescriptor{Name: "x"}, []byte("0123456789"))
	if !errors.Is(err, ErrRedactionFailed) || len(res.Data.Bytes()) != 0 {
		t.Fatalf("oversized: got %q, %v", res.Data.Bytes(), err)
	}
	if _, _, err := small.RedactString(context.Background(), "0123456789"); !errors.Is(err, ErrRedactionFailed) {
		t.Fatalf("oversized string: %v", err)
	}
}

// TestNilRedactorRedacts: a nil redactor is the default one, never a no-op.
func TestNilRedactorRedacts(t *testing.T) {
	var r *Redactor
	out, _ := redactString(t, r, "token="+opaque)
	if strings.Contains(out, opaque) {
		t.Fatalf("nil redactor let the secret through: %q", out)
	}
}

// TestWithLiteral removes the home root from paths; unsafe literals are
// refused.
func TestWithLiteral(t *testing.T) {
	r, err := New(WithLiteral("/home/alice", "home_path"))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := redactString(t, r, "/home/alice/.claude/settings.json and /usr/bin/uname")
	if out != "[REDACTED:home_path]/.claude/settings.json and /usr/bin/uname" {
		t.Fatalf("got %q", out)
	}
	for _, bad := range []string{"/", "//", "ab", `C:\`[:2]} {
		if _, err := New(WithLiteral(bad, "home_path")); err == nil {
			t.Errorf("literal %q accepted", bad)
		}
	}
	if _, err := New(WithLiteral("/home/alice", "Bad Class")); err == nil {
		t.Error("invalid class accepted")
	}
	if _, err := New(WithPattern("custom", "(", 0)); err == nil {
		t.Error("invalid pattern accepted")
	}
}

// TestRedactionLog covers the log helpers.
func TestRedactionLog(t *testing.T) {
	var l RedactionLog
	l = l.Merge(RedactionLog{"b": 1}).Merge(RedactionLog{"a": 2, "b": 1}).Merge(nil)
	if l.Total() != 4 || strings.Join(l.Classes(), ",") != "a,b" {
		t.Fatalf("log %v", l)
	}
}

// TestArgSecretsReachOutput: every secret removed from the arguments is
// returned, and WithSecrets removes it from the output of the same run
// (TF02-AC3: a token in a command argument must not survive an echo).
func TestArgSecretsReachOutput(t *testing.T) {
	args := []string{"--token", opaque, "--password=\"" + opaque + "-2\"", "https://bob:" + opaque + "-3@git.example/x", "ab", "--secret", "xy"}
	out, secrets, _, err := Default().RedactArgsSecrets(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{opaque: true, opaque + "-2": true, opaque + "-3": true, "xy": true}
	for _, s := range secrets {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("secrets %q miss %v (args out %q)", secrets, want, out)
	}
	r := Default().WithSecrets(secrets)
	echo := "got " + opaque + " and " + opaque + "-2 and " + opaque + "-3 and xy\n"
	red, _ := redactString(t, r, echo)
	if strings.Contains(red, opaque) {
		t.Fatalf("echoed secret survived: %q", red)
	}
	if !strings.Contains(red, "and xy") {
		t.Fatalf("a 2-byte value must not be used as a literal: %q", red)
	}
	if plain, _ := redactString(t, Default(), echo); !strings.Contains(plain, opaque) {
		t.Fatal("WithSecrets changed the receiver")
	}
}
