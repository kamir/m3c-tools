package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// The value shape guard of the key name rule (SPEC-0467 section 5.2).
//
// The key name rule replaces the value of a key that sounds like a
// credential. For a credential that is right. For a configuration setting it
// destroys the finding a security review is looking for: an elevated capture
// of an Ubuntu bastion recorded
//
//	ssh/sshd/effective  passwordauthentication = [REDACTED_password]
//	ssh/sshd/effective  permitemptypasswords   = [REDACTED_password]
//	sudo/rule/...       nopasswd               = [REDACTED_password]
//
// so the bundle could not say whether password login is allowed, nor whether
// a sudo rule needs a password. A scan that cannot say "password
// authentication is enabled" is not a scan.
//
// The guard is deliberately a CLOSED set of value tokens, not a heuristic
// about the key: a value that belongs to it cannot carry a secret, whatever
// the key is called. Everything else keeps being replaced, so a key named
// password_hash with a 60 character value is still a secret. The set holds
// the answers configuration files give: the two booleans in their four
// spellings, the words a setting uses instead of a boolean, the OpenSSH
// answers of PermitRootLogin, plus plain integers and durations, which is
// what a timeout, a port, a count or a grace time look like.

// maxPolicyAnswerBytes is the length above which no value is a policy
// answer. The longest member of the set is "forced-commands-only" with 20
// bytes; the cap keeps an entropy carrying value out even if it began with
// one of the prefixes below.
const maxPolicyAnswerBytes = 24

// policyAnswers is the closed set of configuration answers. Lower case; the
// lookup folds case.
var policyAnswers = map[string]bool{
	// the two booleans, in the spellings sshd, sudo, systemd and the JSON of
	// a container runtime use
	"yes":   true,
	"no":    true,
	"true":  true,
	"false": true,
	// the words a setting uses where a boolean does not fit
	"none":    true,
	"any":     true,
	"all":     true,
	"default": true,
	// the answers of sshd_config PermitRootLogin
	"prohibit-password":    true,
	"without-password":     true,
	"forced-commands-only": true,
}

// policyAnswerPrefixes are the answer families that spell a qualifier after
// the answer itself, for example "yes-with-mfa". The qualifier is bounded by
// policyQualifier and by maxPolicyAnswerBytes, so the family cannot become a
// way to smuggle a value past the rule.
var policyAnswerPrefixes = []string{"yes-with-"}

var (
	// policyInteger and policyDuration are NOT part of the generic guard:
	// a number under a key named password is a PIN, not a policy answer, and
	// the guard must not keep it. A probe that knows its own numeric field is
	// configuration declares it (AttributeClass policy), which exempts the
	// field by name instead of by shape. Kept here because IsPolicyNumber
	// serves that declared path and the tests that pin this distinction.
	policyInteger = regexp.MustCompile(`^-?[0-9]{1,10}$`)
	// policyDuration is the "90s", "2m", "1h30m" form of systemd and sshd.
	policyDuration = regexp.MustCompile(`^(?:[0-9]{1,10}(?:ms|s|m|h|d|w))+$`)
	// policyQualifier bounds the tail of a prefix family.
	policyQualifier = regexp.MustCompile(`^[a-z0-9-]{1,12}$`)
)

// IsPolicyAnswer reports whether value is one of the closed set of
// configuration answers and therefore cannot be a credential. Surrounding
// blanks and one pair of quotes are ignored, and the comparison folds case.
// Everything else, in particular every long or high entropy value, is not a
// policy answer.
func IsPolicyAnswer(value string) bool {
	s := strings.TrimSpace(string(unquote([]byte(strings.TrimSpace(value)))))
	if s == "" || len(s) > maxPolicyAnswerBytes {
		return false
	}
	l := strings.ToLower(s)
	if policyAnswers[l] {
		return true
	}
	for _, p := range policyAnswerPrefixes {
		if strings.HasPrefix(l, p) && policyQualifier.MatchString(l[len(p):]) {
			return true
		}
	}
	return false
}

// isPolicyValue reports whether a decoded JSON value cannot be a credential:
// a boolean, a number, or a string that is a policy answer. Everything else,
// including nil and every container, is not.
func isPolicyValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return IsPolicyAnswer(fmt.Sprint(x))
	case float32, float64:
		return false
	case string:
		return IsPolicyAnswer(x)
	case fmt.Stringer:
		return IsPolicyAnswer(x.String())
	}
	return false
}

// ClassDeclaredSensitive is the class of a value replaced because the caller
// declared its key sensitive (ValueContext.SensitiveKeys), whatever the key
// name and the value look like.
const ClassDeclaredSensitive = "declared_sensitive"

// keyPolicy is the per call classification of map keys: what the caller
// declared, and what the key name rule says about everything it did not
// declare.
type keyPolicy struct {
	policy    map[string]bool
	sensitive map[string]bool
}

func newKeyPolicy(vc ValueContext) keyPolicy {
	return keyPolicy{policy: keySet(vc.PolicyKeys), sensitive: keySet(vc.SensitiveKeys)}
}

// keySet normalizes the declared names the way SensitiveKeyClass normalizes
// the key it is given, so "no_passwd", "NOPASSWD" and "noPasswd" are one
// name.
func keySet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[normalizeKey(n)] = true
	}
	return m
}

// markerClass returns the class the value of key is replaced with, and
// whether it is replaced at all. A key the caller declared sensitive is
// always replaced (a declaration in both directions is a caller error and
// fails closed, towards replacement). A key the caller declared policy is
// never replaced because of its name; its value still passes every value
// pattern, so a private key body under a declared policy key is still
// removed. An undeclared key follows the key name rule, unless the value
// itself is a policy answer.
func (kp keyPolicy) markerClass(key string, v any) (string, bool) {
	nk := normalizeKey(key)
	if kp.sensitive[nk] {
		return ClassDeclaredSensitive, true
	}
	if kp.policy[nk] {
		return "", false
	}
	class, ok := SensitiveKeyClass(key)
	if !ok || isPolicyValue(v) {
		return "", false
	}
	return class, true
}

// IsPolicyNumber reports whether value is a plain count, port, uid, timeout or
// duration. It is NOT consulted by the generic key name guard (a number under a
// secret sounding key is a secret); it exists for callers that already know the
// field is configuration.
func IsPolicyNumber(value string) bool {
	l := strings.ToLower(strings.TrimSpace(value))
	return policyInteger.MatchString(l) || policyDuration.MatchString(l)
}
