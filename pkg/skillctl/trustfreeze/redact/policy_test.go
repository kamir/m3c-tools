package redact

import (
	"context"
	"strings"
	"testing"
)

// The value shape guard and the declared key classes (SPEC-0467 section
// 5.2). Every test here has a twin that proves the protection is still
// there: a value that could be a secret is still replaced.

// TestIsPolicyAnswer pins the closed set. The members are the answers a
// configuration file gives; the non members are what a credential looks
// like, including values that start like a member.
func TestIsPolicyAnswer(t *testing.T) {
	members := []string{
		"yes", "no", "true", "false", "YES", "No", "True",
		"none", "any", "all", "ALL", "default",
		"prohibit-password", "without-password", "forced-commands-only",
		"yes-with-mfa",
		" yes ", `"no"`, "'true'",
	}
	for _, m := range members {
		if !IsPolicyAnswer(m) {
			t.Errorf("IsPolicyAnswer(%q) = false, want true", m)
		}
	}
	nonMembers := []string{
		"",
		"maybe",
		"yes please",
		"yes-with-a-very-long-qualifier-that-is-not-one",
		"yesno-hunter2",
		"$6$rounds=656000$abcdefghijklmnop$0123456789ABCDEFGHIJKLMNOPQRSTUV",
		"hunter2",
		// A number is NOT a policy answer to the generic guard: under a key
		// named password a number is a PIN. A probe that knows its own numeric
		// field is configuration declares it by name instead (AttributeClass
		// policy), which is what linux.ssh does for its directives.
		"0", "22", "120", "-1", "4294967295",
		"90s", "2m", "1h30m", "500ms", "7d",
		"12345678901",              // eleven digits is not a count either
		"0123456789abcdef01234567", // 24 bytes of hex is inside the length cap and still not an answer
		"AKIAIOSFODNN7EXAMPLE",
		"/etc/ssh/ssh_host_ed25519_key",
		"2m-and-a-secret",
	}
	for _, n := range nonMembers {
		if IsPolicyAnswer(n) {
			t.Errorf("IsPolicyAnswer(%q) = true, want false", n)
		}
	}
	// The length cap holds whatever the value starts with.
	if IsPolicyAnswer(strings.Repeat("1", maxPolicyAnswerBytes+1)) {
		t.Error("a value longer than the cap was accepted")
	}
}

// TestRedactValueKeepsPolicyAnswers is the measured defect in the structured
// path: the key name says password, the value says what the setting is.
func TestRedactValueKeepsPolicyAnswers(t *testing.T) {
	const hash = "$6$rounds=656000$abcdefghijklmnop$0123456789ABCDEFGHIJKLMNOPQRSTUV"
	in := map[string]string{
		"passwordauthentication": "yes",
		"permitemptypasswords":   "no",
		"nopasswd":               "true",
		"logingracetime":         "120",
		"password_hash":          hash,
	}
	out, log, err := Default().RedactValue(context.Background(), ValueContext{Path: "$"}, in)
	if err != nil {
		t.Fatalf("RedactValue: %v", err)
	}
	got, ok := out.(map[string]string)
	if !ok {
		t.Fatalf("result type %T", out)
	}
	for k, want := range map[string]string{
		"passwordauthentication": "yes",
		"permitemptypasswords":   "no",
		"nopasswd":               "true",
		"logingracetime":         "120",
		"password_hash":          Marker("password"),
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	// Exactly one replacement: the guard must not silently count the four
	// answers it kept.
	if log.Total() != 1 {
		t.Errorf("redaction log %+v, want one replacement", log)
	}
}

// TestRedactValueKeepsBooleansAndNumbers: a decoded JSON boolean or number
// under a sensitive key is not a credential either.
func TestRedactValueKeepsBooleansAndNumbers(t *testing.T) {
	in := map[string]any{"nopasswd": true, "max_auth_tries": 3, "session_token": "opaque-S3CR3T-value-0123456789"}
	out, _, err := Default().RedactValue(context.Background(), ValueContext{}, in)
	if err != nil {
		t.Fatalf("RedactValue: %v", err)
	}
	got := out.(map[string]any)
	if got["nopasswd"] != true {
		t.Errorf("nopasswd = %#v, want true", got["nopasswd"])
	}
	if got["max_auth_tries"] != 3 {
		t.Errorf("max_auth_tries = %#v, want 3", got["max_auth_tries"])
	}
	if got["session_token"] != Marker("token") {
		t.Errorf("session_token = %#v, want the token marker", got["session_token"])
	}
}

// TestRedactValueDeclaredPolicyKey: a caller that knows its own field says
// so, and then even a value outside the closed set survives. The value
// patterns still run, so a private key body under the same key is removed.
func TestRedactValueDeclaredPolicyKey(t *testing.T) {
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	in := map[string]string{
		"passwordauthentication": "yes-if-pam-says-so",
		"permitemptypasswords":   pem,
		"client_secret":          "yes-if-pam-says-so",
	}
	vc := ValueContext{PolicyKeys: []string{"PasswordAuthentication", "permit_empty_passwords"}}
	out, _, err := Default().RedactValue(context.Background(), vc, in)
	if err != nil {
		t.Fatalf("RedactValue: %v", err)
	}
	got := out.(map[string]string)
	if got["passwordauthentication"] != "yes-if-pam-says-so" {
		t.Errorf("a declared policy value was replaced: %q", got["passwordauthentication"])
	}
	if strings.Contains(got["permitemptypasswords"], "b3BlbnNzaC1rZXktdjEAAAAA") {
		t.Errorf("a private key body survived under a declared policy key: %q", got["permitemptypasswords"])
	}
	// The declaration holds for the names it lists, not for every key that
	// sounds alike.
	if got["client_secret"] != Marker("client_secret") {
		t.Errorf("client_secret = %q, want the marker", got["client_secret"])
	}
}

// TestRedactValueDeclaredSensitiveKey is the other half: a caller can force
// the replacement for a key the name rule knows nothing about, and a name
// declared in both directions is sensitive.
func TestRedactValueDeclaredSensitiveKey(t *testing.T) {
	in := map[string]string{"key_material": "AAAAC3NzaC1lZDI1NTE5", "nopasswd": "true"}
	vc := ValueContext{
		PolicyKeys:    []string{"nopasswd", "key_material"},
		SensitiveKeys: []string{"key_material"},
	}
	out, _, err := Default().RedactValue(context.Background(), vc, in)
	if err != nil {
		t.Fatalf("RedactValue: %v", err)
	}
	got := out.(map[string]string)
	if got["key_material"] != Marker(ClassDeclaredSensitive) {
		t.Errorf("key_material = %q, want %q", got["key_material"], Marker(ClassDeclaredSensitive))
	}
	if got["nopasswd"] != "true" {
		t.Errorf("nopasswd = %q, want true", got["nopasswd"])
	}
}

// TestRedactBytesKeepsPolicyAnswerInText: the same guard in the text path.
// Without it the evidence of a sudoers file reads "NOPASSWD:
// [REDACTED_password]", which removes the command set of the rule from the
// one file a reviewer reads.
func TestRedactBytesKeepsPolicyAnswerInText(t *testing.T) {
	const line = "alice ALL=(ALL) NOPASSWD: ALL\n" +
		"PasswordAuthentication yes\n" +
		"permit_empty_passwords=no\n" +
		"client_secret=Zx9-opaque-value-0123456789\n"
	out, log, err := Default().RedactString(context.Background(), line)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	for _, want := range []string{"NOPASSWD: ALL", "permit_empty_passwords=no"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is gone from %q", want, out)
		}
	}
	if strings.Contains(out, "Zx9-opaque-value-0123456789") {
		t.Errorf("the client secret survived: %q", out)
	}
	if log.Total() != 1 {
		t.Errorf("redaction log %+v, want one replacement", log)
	}
}

// TestRedactBytesKeepsAPathSegmentIntact: the last segment of a path is not
// a key. Measured on the recorded refusal of the trial host, where the file
// name carries the word passwd and the message after it was replaced.
func TestRedactBytesKeepsAPathSegmentIntact(t *testing.T) {
	const line = "cat: /etc/sudoers.d/alice-nopasswd: Permission denied"
	out, log, err := Default().RedactString(context.Background(), line)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	if out != line {
		t.Fatalf("the refusal was changed to %q", out)
	}
	if log.Total() != 0 {
		t.Fatalf("redaction log %+v, want nothing", log)
	}
}

// TestRedactBytesStillTakesRealKeys is the twin of the two text guards: the
// shapes a credential really comes in are still replaced.
func TestRedactBytesStillTakesRealKeys(t *testing.T) {
	cases := []string{
		"password=hunter2-opaque-value",
		`"password": "hunter2-opaque-value"`,
		"PGPASSWORD=hunter2-opaque-value psql",
		`HKLM\Software\App\Password=hunter2-opaque-value`,
		"client_secret: 'hunter2-opaque-value'",
		"/etc/app.conf: token=hunter2-opaque-value",
	}
	for _, in := range cases {
		out, _, err := Default().RedactString(context.Background(), in)
		if err != nil {
			t.Fatalf("RedactString(%q): %v", in, err)
		}
		if strings.Contains(out, "hunter2-opaque-value") {
			t.Errorf("the secret survived in %q: %q", in, out)
		}
	}
	// A bare flag and its value are the argument vector path, where the
	// value stands alone and has no key beside it.
	args, _, err := Default().RedactArgs(context.Background(), []string{"psql", "--password", "hunter2-opaque-value"})
	if err != nil {
		t.Fatalf("RedactArgs: %v", err)
	}
	if strings.Join(args, " ") != "psql --password "+Marker("password") {
		t.Errorf("RedactArgs kept the value: %v", args)
	}
}

// A number under a secret sounding key is a PIN, not a policy answer. The
// generic guard must not keep it; only a probe that declares the field as
// configuration may. Measured consequence of the opposite: a six digit PIN
// written as password=123456 survived the key name rule.
func TestNumberUnderASecretKeyIsStillRedacted(t *testing.T) {
	r := Default()
	// "pin: 1234" is deliberately NOT in this list: the vocabulary does not
	// know the word pin, because as a substring it also hits "pinned" and
	// "pinning", which name the skillctl pin feature all over this tree. A
	// numeric secret under a key the vocabulary does not know is out of reach
	// of the key name rule either way, with or without this guard.
	for _, line := range []string{"password=123456", "PGPASSWORD=90", `{"password": 123456}`} {
		out, err := r.RedactBytes(context.Background(), EvidenceDescriptor{}, []byte(line))
		if err != nil {
			t.Fatalf("RedactBytes(%q): %v", line, err)
		}
		if !strings.Contains(string(out.Data.Bytes()), "[REDACTED_") {
			t.Errorf("RedactBytes(%q) = %q, want the value replaced", line, out.Data.Bytes())
		}
	}
	if IsPolicyNumber("1234") != true {
		t.Error("IsPolicyNumber lost the shape a declaring probe relies on")
	}
}
