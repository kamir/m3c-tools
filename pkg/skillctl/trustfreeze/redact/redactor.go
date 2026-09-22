package redact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ErrRedactionFailed is wrapped by every redaction failure. Callers treat it
// fail-closed: the affected evidence is dropped, never persisted unredacted
// (SPEC-0467 R5).
var ErrRedactionFailed = errors.New("redact: redaction failed")

// DefaultMaxInputBytes caps one RedactBytes input. Larger input is refused
// (fail-closed) instead of being scanned partially.
const DefaultMaxInputBytes = 16 << 20

// markerPrefix starts every replacement.
const markerPrefix = "[REDACTED:"

// Marker returns the replacement text for class, "[REDACTED:<class>]".
func Marker(class string) string { return markerPrefix + class + "]" }

var exactMarker = regexp.MustCompile(`^\[REDACTED:[a-z0-9_]+\]$`)

// isMarker reports whether s is exactly one replacement marker.
func isMarker(s []byte) bool { return exactMarker.Match(s) }

// Default pattern classes.
//
// #nosec G101 -- das sind die NAMEN der Fundklassen, die der Redactor in seinen
// Bericht schreibt, keine Zugangsdaten. Ausgerechnet das Paket, das Secrets von
// der Platte fernhaelt, wird hier gemeldet, weil zwei Namen "jwt" und
// "url_credential" lauten.
const (
	ClassPrivateKey    = "private_key"
	ClassCookie        = "cookie"
	ClassAuthorization = "authorization"
	ClassBearerToken   = "bearer_token"
	ClassAWSAccessKey  = "aws_access_key_id"
	ClassGitHubToken   = "github_token"
	ClassSlackToken    = "slack_token"
	ClassJWT           = "jwt"
	ClassURLCredential = "url_credential"
)

// rule is one pattern. group names the submatch that is replaced (0 is the
// whole match). A quoted value keeps its quotes.
type rule struct {
	class string
	re    *regexp.Regexp
	group int
	// keyGroup, when > 0, names the submatch holding a key; the class is then
	// derived from the key (see SensitiveKeyClass).
	keyGroup int
}

// sensitiveWords is the key vocabulary of SPEC-0467 R5 and the Trust Freeze
// redaction policy: password, passwd, secret, token, api key, access key,
// private key, client secret, refresh token, cookie, session.
const sensitiveWords = `(?:password|passwd|passphrase|secret|token|api[_\- ]?key|access[_\- ]?key|private[_\- ]?key|client[_\- ]?secret|refresh[_\- ]?token|cookie|session)`

func defaultRules() []rule {
	return []rule{
		{class: ClassPrivateKey, re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----|\z)`)},
		{class: ClassCookie, re: regexp.MustCompile(`(?im)^([ \t]*(?:set-)?cookie[ \t]*:[ \t]*)([^\r\n]+)`), group: 2},
		{class: ClassAuthorization, re: regexp.MustCompile(`(?i)(authorization["']?[ \t]*[:=][ \t]*["']?(?:(?:bearer|basic|digest|token|negotiate|ntlm)[ \t]+)?)([^\s"',;]+)`), group: 2},
		{class: ClassBearerToken, re: regexp.MustCompile(`(?i)\b(bearer[ \t]+)([A-Za-z0-9\-._~+/]+=*)`), group: 2},
		{class: ClassAWSAccessKey, re: regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`), group: 1},
		{class: ClassGitHubToken, re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`), group: 1},
		{class: ClassSlackToken, re: regexp.MustCompile(`\b(xox[abposr]-[A-Za-z0-9-]{10,})`), group: 1},
		{class: ClassJWT, re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)`), group: 1},
		// user:password@ in URLs, for example git remotes with a token.
		{class: ClassURLCredential, re: regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://[^\s/:@"']+:)([^\s/@"']+)@`), group: 2},
		// key/value pairs: KEY=VALUE, KEY: VALUE, "key": "value", --key=value.
		{
			re:       regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*` + sensitiveWords + `[A-Za-z0-9_.\-]*)("?'?[ \t]*[:=][ \t]*)("(?:[^"\\\r\n]|\\.)*"?|'[^'\r\n]*'?|[^\s"'&]+)`),
			group:    3,
			keyGroup: 1,
		},
	}
}

type literal struct {
	value []byte
	class string
}

// Redactor replaces secrets with "[REDACTED:<class>]" markers. It is safe for
// concurrent use. A nil *Redactor behaves like Default(): there is no way to
// call it and get unredacted output back.
type Redactor struct {
	rules    []rule
	literals []literal
	maxInput int
}

// Option configures New.
type Option func(*Redactor) error

// WithLiteral replaces every occurrence of value with "[REDACTED:<class>]"
// before the patterns run. Use it for values that must never appear in a
// bundle, such as the user home directory. Values shorter than 3 bytes or
// consisting only of path separators are refused, because replacing them
// would destroy unrelated output.
func WithLiteral(value, class string) Option {
	return func(r *Redactor) error {
		if len(value) < 3 || strings.Trim(value, `/\`) == "" {
			return fmt.Errorf("%w: literal %q is too short to redact safely", ErrRedactionFailed, value)
		}
		if err := checkClass(class); err != nil {
			return err
		}
		r.literals = append(r.literals, literal{value: []byte(value), class: class})
		return nil
	}
}

// WithMaxInputBytes sets the largest input RedactBytes accepts. Larger input
// fails with ErrRedactionFailed.
func WithMaxInputBytes(n int) Option {
	return func(r *Redactor) error {
		if n <= 0 {
			return fmt.Errorf("%w: max input bytes must be positive", ErrRedactionFailed)
		}
		r.maxInput = n
		return nil
	}
}

// WithPattern adds a pattern whose submatch group is replaced with
// "[REDACTED:<class>]". Group 0 replaces the whole match.
func WithPattern(class, pattern string, group int) Option {
	return func(r *Redactor) error {
		if err := checkClass(class); err != nil {
			return err
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("%w: pattern for %s: %w", ErrRedactionFailed, class, err)
		}
		if group < 0 || group > re.NumSubexp() {
			return fmt.Errorf("%w: pattern for %s has no group %d", ErrRedactionFailed, class, group)
		}
		r.rules = append(r.rules, rule{class: class, re: re, group: group})
		return nil
	}
}

func checkClass(class string) error {
	if !exactMarker.MatchString(Marker(class)) {
		return fmt.Errorf("%w: class %q must be lowercase letters, digits and '_'", ErrRedactionFailed, class)
	}
	return nil
}

// New returns a redactor with the default patterns plus the options.
func New(opts ...Option) (*Redactor, error) {
	r := &Redactor{rules: defaultRules(), maxInput: DefaultMaxInputBytes}
	for _, o := range opts {
		if err := o(r); err != nil {
			return nil, err
		}
	}
	// Longer literals first, so a literal that contains another one wins.
	sort.SliceStable(r.literals, func(i, j int) bool { return len(r.literals[i].value) > len(r.literals[j].value) })
	return r, nil
}

var (
	defaultOnce     sync.Once
	defaultRedactor *Redactor
)

// Default returns the shared redactor with only the default patterns.
func Default() *Redactor {
	defaultOnce.Do(func() {
		r, err := New()
		if err != nil {
			panic(err) // the default patterns are constants
		}
		defaultRedactor = r
	})
	return defaultRedactor
}

func (r *Redactor) self() *Redactor {
	if r == nil {
		return Default()
	}
	return r
}

// RedactionLog counts replacements per class.
type RedactionLog map[string]int

// Total returns the number of replacements.
func (l RedactionLog) Total() int {
	n := 0
	for _, c := range l {
		n += c
	}
	return n
}

// Classes returns the classes with at least one replacement, sorted.
func (l RedactionLog) Classes() []string {
	out := make([]string, 0, len(l))
	for c, n := range l {
		if n > 0 {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// Merge adds the counts of o to l and returns l (allocating when l is nil).
func (l RedactionLog) Merge(o RedactionLog) RedactionLog {
	if len(o) == 0 {
		return l
	}
	if l == nil {
		l = RedactionLog{}
	}
	for c, n := range o {
		l[c] += n
	}
	return l
}

// EvidenceDescriptor names the bytes being redacted, for error messages.
type EvidenceDescriptor struct {
	ProbeID string
	Name    string
	Source  string
}

// RedactionResult is the outcome of RedactBytes.
type RedactionResult struct {
	Data Redacted
	Log  RedactionLog
}

// RedactBytes redacts b. On error the result carries no data.
func (r *Redactor) RedactBytes(ctx context.Context, d EvidenceDescriptor, b []byte) (RedactionResult, error) {
	r = r.self()
	if err := ctx.Err(); err != nil {
		return RedactionResult{}, fmt.Errorf("%w: %s: %w", ErrRedactionFailed, d.label(), err)
	}
	if len(b) > r.maxInput {
		return RedactionResult{}, fmt.Errorf("%w: %s: input of %d bytes exceeds the %d byte limit", ErrRedactionFailed, d.label(), len(b), r.maxInput)
	}
	out, log := r.apply(b)
	return RedactionResult{Data: newRedacted(out), Log: log}, nil
}

func (d EvidenceDescriptor) label() string {
	parts := []string{}
	for _, s := range []string{d.ProbeID, d.Name, d.Source} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "evidence"
	}
	return strings.Join(parts, "/")
}

// RedactString redacts one string.
func (r *Redactor) RedactString(ctx context.Context, s string) (string, RedactionLog, error) {
	r = r.self()
	if err := ctx.Err(); err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrRedactionFailed, err)
	}
	if len(s) > r.maxInput {
		return "", nil, fmt.Errorf("%w: string of %d bytes exceeds the %d byte limit", ErrRedactionFailed, len(s), r.maxInput)
	}
	out, log := r.apply([]byte(s))
	return string(out), log, nil
}

// RedactArgs redacts a command argument vector. Each argument is redacted on
// its own; in addition, the argument after a flag whose name is a sensitive
// key ("--token", "-password") and that carries no "=" is replaced
// wholesale, because a bare value has no context of its own.
func (r *Redactor) RedactArgs(ctx context.Context, args []string) ([]string, RedactionLog, error) {
	out, _, log, err := r.RedactArgsSecrets(ctx, args)
	return out, log, err
}

// RedactArgsSecrets is RedactArgs that also returns every secret value it
// removed. A runner passes them to WithSecrets so that a tool which echoes
// its own arguments cannot leak them through its output.
func (r *Redactor) RedactArgsSecrets(ctx context.Context, args []string) ([]string, []string, RedactionLog, error) {
	r = r.self()
	out := make([]string, len(args))
	var secrets []string
	var log RedactionLog
	for i := 0; i < len(args); i++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %w", ErrRedactionFailed, err)
		}
		if len(args[i]) > r.maxInput {
			return nil, nil, nil, fmt.Errorf("%w: argument of %d bytes exceeds the %d byte limit", ErrRedactionFailed, len(args[i]), r.maxInput)
		}
		b, l := r.applyCollect([]byte(args[i]), &secrets)
		out[i] = string(b)
		log = log.Merge(l)
		if class, ok := flagClass(args[i]); ok && i+1 < len(args) {
			i++
			if isMarker([]byte(args[i])) {
				out[i] = args[i]
				continue
			}
			secrets = append(secrets, args[i])
			out[i] = Marker(class)
			log = log.Merge(RedactionLog{class: 1})
		}
	}
	return out, secrets, log, nil
}

// ClassArgSecret marks a value removed from tool output because the same
// value was redacted from the command arguments.
const ClassArgSecret = "arg_secret"

// minSecretLiteral is the shortest secret WithSecrets removes from output;
// shorter values would destroy unrelated text.
const minSecretLiteral = 3

// WithSecrets returns a redactor that, before its patterns, also replaces
// every given value of at least 3 bytes with "[REDACTED:arg_secret]". r
// is not changed. Values that are markers are ignored.
func (r *Redactor) WithSecrets(values []string) *Redactor {
	r = r.self()
	c := &Redactor{rules: r.rules, maxInput: r.maxInput, literals: append([]literal(nil), r.literals...)}
	for _, v := range values {
		if len(v) < minSecretLiteral || isMarker([]byte(v)) {
			continue
		}
		c.literals = append(c.literals, literal{value: []byte(v), class: ClassArgSecret})
	}
	sort.SliceStable(c.literals, func(i, j int) bool { return len(c.literals[i].value) > len(c.literals[j].value) })
	return c
}

// flagClass reports whether arg is a flag without "=" whose name is a
// sensitive key.
func flagClass(arg string) (string, bool) {
	if !strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "=:") {
		return "", false
	}
	return SensitiveKeyClass(strings.TrimLeft(arg, "-"))
}

// ErrUnsupportedValue is wrapped when RedactValue meets a type it cannot walk.
var ErrUnsupportedValue = errors.New("redact: unsupported value type")

// ValueContext names the value being redacted, for error messages.
type ValueContext struct {
	ProbeID string
	Path    string
}

// RedactValue redacts a decoded JSON-like value: strings are redacted with
// the patterns; the value of every map key that is a sensitive key
// (SensitiveKeyClass) is replaced by the marker whatever its type; map keys
// are redacted too. Numbers, booleans and nil pass unchanged. Supported types:
// string, bool, nil, all integer and float kinds, json.Number (any type with a
// numeric String method passes unchanged), []any, []string,
// map[string]any and map[string]string. Any other type fails with
// ErrUnsupportedValue, so an unknown container is never persisted unscanned.
// The input is not modified.
func (r *Redactor) RedactValue(ctx context.Context, vc ValueContext, v any) (any, RedactionLog, error) {
	r = r.self()
	var log RedactionLog
	out, err := r.redactValue(ctx, v, vc.Path, 0, &log)
	if err != nil {
		return nil, nil, err
	}
	return out, log, nil
}

const maxValueDepth = 256

func (r *Redactor) redactValue(ctx context.Context, v any, at string, depth int, log *RedactionLog) (any, error) {
	if depth > maxValueDepth {
		return nil, fmt.Errorf("%w: %w: nesting deeper than %d at %s", ErrRedactionFailed, ErrUnsupportedValue, maxValueDepth, at)
	}
	switch x := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return x, nil
	case string:
		s, l, err := r.RedactString(ctx, x)
		if err != nil {
			return nil, err
		}
		*log = log.Merge(l)
		return s, nil
	case fmt.Stringer:
		// json.Number and similar string-backed number types pass unchanged
		// (with their type) when their text is a number.
		if isNumberText(x.String()) {
			return x, nil
		}
		return nil, fmt.Errorf("%w: %w: %T at %s", ErrRedactionFailed, ErrUnsupportedValue, v, at)
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			red, l, err := r.RedactString(ctx, s)
			if err != nil {
				return nil, err
			}
			*log = log.Merge(l)
			out[i] = red
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			red, err := r.redactValue(ctx, e, fmt.Sprintf("%s[%d]", at, i), depth+1, log)
			if err != nil {
				return nil, err
			}
			out[i] = red
		}
		return out, nil
	case map[string]string:
		out := make(map[string]string, len(x))
		for _, k := range sortedKeys(x) {
			nk, err := r.redactKey(ctx, k, func(s string) bool { _, ok := out[s]; return ok }, log)
			if err != nil {
				return nil, err
			}
			if class, ok := SensitiveKeyClass(k); ok {
				out[nk] = r.keyedMarker(x[k], class, log)
				continue
			}
			s, l, err := r.RedactString(ctx, x[k])
			if err != nil {
				return nil, err
			}
			*log = log.Merge(l)
			out[nk] = s
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for _, k := range sortedKeys(x) {
			nk, err := r.redactKey(ctx, k, func(s string) bool { _, ok := out[s]; return ok }, log)
			if err != nil {
				return nil, err
			}
			if class, ok := SensitiveKeyClass(k); ok {
				s, _ := x[k].(string)
				out[nk] = r.keyedMarker(s, class, log)
				continue
			}
			red, err := r.redactValue(ctx, x[k], at+"."+k, depth+1, log)
			if err != nil {
				return nil, err
			}
			out[nk] = red
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: %w: %T at %s", ErrRedactionFailed, ErrUnsupportedValue, v, at)
}

// keyedMarker returns the marker for the value of a sensitive key. A value
// that already is exactly one marker is kept, so a second pass is a no-op.
func (r *Redactor) keyedMarker(s, class string, log *RedactionLog) string {
	if isMarker([]byte(s)) {
		return s
	}
	*log = log.Merge(RedactionLog{class: 1})
	return Marker(class)
}

// redactKey redacts a map key. A key that, after redaction, collides with a
// key already present is refused (fail-closed: two different secrets must
// not merge silently).
func (r *Redactor) redactKey(ctx context.Context, k string, taken func(string) bool, log *RedactionLog) (string, error) {
	nk, l, err := r.RedactString(ctx, k)
	if err != nil {
		return "", err
	}
	if taken(nk) {
		return "", fmt.Errorf("%w: map key %q collides with another key after redaction", ErrRedactionFailed, nk)
	}
	*log = log.Merge(l)
	return nk, nil
}

func isNumberText(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '-' && c != '+' && c != '.' && c != 'e' && c != 'E' {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SensitiveKeyClass reports whether key names a secret (password, passwd,
// passphrase, secret, token, api key, access key, private key, client secret,
// refresh token, cookie, session; case, "_", "-", "." and spaces ignored) and
// returns the redaction class for it.
func SensitiveKeyClass(key string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	k := b.String()
	for _, w := range keyClasses {
		if strings.Contains(k, w.word) {
			return w.class, true
		}
	}
	return "", false
}

// keyClasses is ordered: the more specific word wins.
var keyClasses = []struct{ word, class string }{
	{"refreshtoken", "refresh_token"},
	{"clientsecret", "client_secret"},
	{"privatekey", "private_key"},
	{"accesskey", "access_key"},
	{"apikey", "api_key"},
	{"passphrase", "password"},
	{"password", "password"},
	{"passwd", "password"},
	{"secret", "secret"},
	{"token", "token"},
	{"cookie", "cookie"},
	{"session", "session"},
}

// apply runs literals, then every rule in order, over b.
func (r *Redactor) apply(b []byte) ([]byte, RedactionLog) {
	return r.applyCollect(b, nil)
}

// applyCollect is apply that also appends every replaced value to secrets
// when secrets is not nil.
func (r *Redactor) applyCollect(b []byte, secrets *[]string) ([]byte, RedactionLog) {
	var log RedactionLog
	out := b
	for _, lit := range r.literals {
		if n := bytes.Count(out, lit.value); n > 0 {
			out = bytes.ReplaceAll(out, lit.value, []byte(Marker(lit.class)))
			log = log.Merge(RedactionLog{lit.class: n})
		}
	}
	for _, ru := range r.rules {
		out = ru.replace(out, &log, secrets)
	}
	// out may alias b; RedactBytes and RedactString copy before returning.
	return out, log
}

func (ru rule) replace(b []byte, log *RedactionLog, secrets *[]string) []byte {
	matches := ru.re.FindAllSubmatchIndex(b, -1)
	if len(matches) == 0 {
		return b
	}
	var buf bytes.Buffer
	buf.Grow(len(b))
	last := 0
	for _, m := range matches {
		s, e := m[2*ru.group], m[2*ru.group+1]
		if s < 0 || s < last {
			continue
		}
		val := b[s:e]
		class := ru.class
		if ru.keyGroup > 0 {
			ks, ke := m[2*ru.keyGroup], m[2*ru.keyGroup+1]
			c, ok := SensitiveKeyClass(string(b[ks:ke]))
			if !ok {
				continue
			}
			class = c
		}
		repl, changed := quotedReplacement(val, class)
		if !changed {
			continue
		}
		if secrets != nil {
			*secrets = append(*secrets, string(unquote(val)))
		}
		buf.Write(b[last:s])
		buf.WriteString(repl)
		last = e
		*log = log.Merge(RedactionLog{class: 1})
	}
	if last == 0 {
		return b
	}
	buf.Write(b[last:])
	return buf.Bytes()
}

// unquote strips one pair of surrounding quotes (or an opening quote).
func unquote(val []byte) []byte {
	if len(val) > 0 && (val[0] == '"' || val[0] == '\'') {
		q := val[0]
		inner := val[1:]
		if len(inner) > 0 && inner[len(inner)-1] == q {
			inner = inner[:len(inner)-1]
		}
		return inner
	}
	return val
}

// quotedReplacement returns the replacement for val. A quoted value keeps its
// quotes. A value that already is exactly one marker is left alone.
func quotedReplacement(val []byte, class string) (string, bool) {
	if len(val) == 0 {
		return "", false
	}
	q := val[0]
	if q == '"' || q == '\'' {
		inner := val[1:]
		closed := len(inner) > 0 && inner[len(inner)-1] == q
		if closed {
			inner = inner[:len(inner)-1]
		}
		if len(inner) == 0 || isMarker(inner) {
			return "", false
		}
		if closed {
			return string(q) + Marker(class) + string(q), true
		}
		return string(q) + Marker(class), true
	}
	if isMarker(val) {
		return "", false
	}
	return Marker(class), true
}
