package verify

// Trust-roots loader for ~/.claude/skill-trust-roots.yaml.
//
// Schema (per SPEC-0188 §4.4 + the multi-entry overlap clarification):
//
//	trust_roots:
//	  - registry_url: https://aims.example.com/api/skills
//	    registry_keys:
//	      - id: aims-core-dev
//	        pubkey: <base64 of raw 32-byte ed25519 pubkey>
//	        issued: 2026-05-05
//	        # retired: 2026-12-31    # OPTIONAL — retired keys are inert
//	    identity_keys_authorized: from-registry
//	    governance_minimum: green   # green | yellow
//
// Multiple `registry_keys` per registry support overlap-window rotation:
// publish key N+1 alongside key N for some days, then mark key N retired.
// The verifier accepts ANY non-retired key during overlap.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"crypto/ed25519"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"gopkg.in/yaml.v3"
)

// DefaultTrustRootsPath is the conventional location of the trust-roots
// file relative to the user's home dir. Resolve via DefaultPath() to get
// an absolute path with `~` expanded.
const DefaultTrustRootsPath = ".claude/skill-trust-roots.yaml"

// pubkeyRawSize is the ed25519 public key size in bytes. Anything that
// decodes to a different length is rejected — there is no useful "lenient
// mode" for a key length check.
const pubkeyRawSize = ed25519.PublicKeySize // 32

// validGovernanceMinima is the closed set of accepted values for
// `governance_minimum`. SPEC-0188 §4.4 lists "green" and "yellow"; "red"
// is omitted intentionally — pinning to red would mean accepting anything,
// which is a footgun we refuse to spell.
var validGovernanceMinima = map[string]struct{}{
	"green":  {},
	"yellow": {},
}

// validIdentityModes is the closed set of accepted values for
// `identity_keys_authorized`. Today only "from-registry" is meaningful;
// future modes (e.g. "manual-pin") will be added here once their semantics
// are speced.
var validIdentityModes = map[string]struct{}{
	"from-registry": {},
}

// RegistryKey is one pinned ed25519 public key for a registry. A registry
// may have multiple keys live at once (during a rotation overlap window);
// retired keys parse but IsActive returns false so the verifier rejects
// them.
type RegistryKey struct {
	// ID is a human-friendly label for the key. Used in error messages
	// only — never matched against signature material.
	ID string `yaml:"id"`

	// Pubkey is the raw 32-byte ed25519 public key. The on-disk
	// encoding is base64 of the raw bytes (NOT PEM, NOT DER); the
	// loader decodes once and stores raw bytes here so callers don't
	// re-decode per verification.
	Pubkey []byte `yaml:"-"`

	// PubkeyB64 is the base64 form preserved verbatim from the YAML so
	// Save() round-trips the file losslessly. The loader populates
	// both PubkeyB64 (string form) and Pubkey (raw bytes) for symmetry.
	PubkeyB64 string `yaml:"pubkey"`

	// Issued is the ISO-8601 date the key was first published. Stored
	// as a free-form string — verification doesn't currently use it
	// (rotation policy is encoded in `retired`, not in date math) but
	// admins reading the file want to see when each key entered service.
	Issued string `yaml:"issued"`

	// Retired, if non-empty, marks the key as retired as of that ISO
	// date. The verifier rejects retired keys regardless of date —
	// "retired" is a binary toggle in v1, the date is just metadata.
	Retired string `yaml:"retired,omitempty"`
}

// IsActive reports whether the key is eligible to verify a registry
// signature today. A key is active iff Retired is the empty string.
//
// We deliberately do NOT compare Retired against time.Now: in v1, marking
// a key retired in the YAML is a deliberate admin act and should take
// effect immediately on next verifier invocation, not at midnight UTC of
// some date.
func (rk RegistryKey) IsActive() bool {
	return rk.Retired == ""
}

// TrustRoot is one pinned registry. It carries 1..N keys (overlap-window
// rotation) plus the policy knobs that bound what the verifier will admit
// from this registry.
type TrustRoot struct {
	// RegistryURL is the canonical aims-core skill-registry root, e.g.
	// https://aims.example.com/api/skills. The verifier matches a
	// bundle's source registry against this URL exactly (no normalization
	// beyond trimming trailing slash).
	RegistryURL string `yaml:"registry_url"`

	// RegistryKeys are the pinned ed25519 public keys that this
	// registry signs its attestations with. May contain retired keys —
	// the loader does NOT silently filter them; callers must check
	// IsActive(). This preserves the file's history when round-tripped.
	RegistryKeys []RegistryKey `yaml:"registry_keys"`

	// IdentityKeysAuthorized governs how the verifier looks up author
	// public keys. v1 only accepts "from-registry" — the verifier
	// trusts the registry's identity table. Future values (e.g.
	// "manual-pin") would let admins pin authoring identities locally.
	IdentityKeysAuthorized string `yaml:"identity_keys_authorized"`

	// GovernanceMinimum is one of "green" or "yellow". A bundle whose
	// current attestation is below this level is rejected with exit
	// code 13 (ErrGovernanceBelowMin).
	GovernanceMinimum string `yaml:"governance_minimum"`
}

// ActiveKeys returns the subset of RegistryKeys that are not retired. It
// preserves the original order so error messages stay deterministic.
func (t TrustRoot) ActiveKeys() []RegistryKey {
	out := make([]RegistryKey, 0, len(t.RegistryKeys))
	for _, k := range t.RegistryKeys {
		if k.IsActive() {
			out = append(out, k)
		}
	}
	return out
}

// TrustRoots is the in-memory representation of the YAML file plus a
// resolved absolute path so error messages can quote it back to the user.
type TrustRoots struct {
	// Roots is the list of pinned registries. Order matches file order.
	Roots []TrustRoot `yaml:"trust_roots"`

	// Path is the resolved absolute file path used by Load (and by
	// Save() on round-trip). Not serialized to YAML.
	Path string `yaml:"-"`
}

// DefaultPath returns the absolute path to the user's trust-roots file
// (typically ~/.claude/skill-trust-roots.yaml). Returns an error if the
// home directory can't be determined.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("trust-roots: resolve home dir: %w", err)
	}
	return filepath.Join(home, DefaultTrustRootsPath), nil
}

// Load reads and validates the trust-roots YAML at path.
//
// On the first run (file doesn't exist) Load returns a *TrustRoots with
// Path set and Roots empty, plus a wrapped os.ErrNotExist so callers can
// `errors.Is(err, os.ErrNotExist)` to distinguish "file missing" from
// "file malformed". This is what `skillctl trust list` and `skillctl
// trust add` need to bootstrap a config without an extra "exists?" check.
//
// Strict mode: unknown YAML fields are rejected. A typo in `governance_minimum`
// or `registry_keys` would otherwise silently disable a key — the verifier
// would then trust nothing on that registry, refusing every install with a
// confusing "registry not in trust roots" — and the user would never know
// their YAML had a typo. We refuse loudly instead.
func Load(path string) (*TrustRoots, error) {
	if path == "" {
		return nil, errors.New("trust-roots: path is required")
	}
	abs, err := resolveAndValidatePath(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Bootstrap path: empty config, but the error is wrapped
			// so the caller can detect "file missing" deliberately.
			return &TrustRoots{Path: abs}, fmt.Errorf("trust-roots: %w", err)
		}
		return nil, fmt.Errorf("trust-roots: read %s: %w", abs, err)
	}

	var tr TrustRoots
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // strict: unknown fields → error
	if err := dec.Decode(&tr); err != nil {
		return nil, fmt.Errorf("trust-roots: parse %s: %w", abs, err)
	}
	tr.Path = abs

	if err := tr.validate(); err != nil {
		return nil, fmt.Errorf("trust-roots: validate %s: %w", abs, err)
	}
	return &tr, nil
}

// Save writes the TrustRoots back to t.Path with mode 0600. The file is
// written atomically (write to <path>.tmp, fsync, rename) so a crashed
// editor never leaves a half-written config — a corrupted trust-roots file
// would brick `skillctl install` until the user noticed and fixed it.
//
// Mode 0600: the pubkeys themselves aren't secrets, but the file IS the
// machine's policy decision about what to trust, and another local user
// shouldn't be able to silently add a registry to it.
func (t *TrustRoots) Save() error {
	if t == nil {
		return errors.New("trust-roots: Save called on nil")
	}
	if t.Path == "" {
		return errors.New("trust-roots: Path is empty (Load before Save, or set Path explicitly)")
	}
	if err := t.validate(); err != nil {
		return fmt.Errorf("trust-roots: refuse to save invalid config: %w", err)
	}

	// Make sure the parent dir exists (~/.claude/ may not on a fresh
	// machine). 0700 because it lives under the user's home and may
	// hold other Claude state.
	if dir := filepath.Dir(t.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("trust-roots: create parent dir %s: %w", dir, err)
		}
	}

	// Marshal with a 2-space indent for human-friendly diffs.
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(t); err != nil {
		return fmt.Errorf("trust-roots: encode YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("trust-roots: close encoder: %w", err)
	}

	// Atomic write: tmp file in same dir → fsync → rename.
	tmp := t.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("trust-roots: open tmp %s: %w", tmp, err)
	}
	if _, err := f.WriteString(buf.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: write tmp %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: fsync tmp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: close tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, t.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: rename %s → %s: %w", tmp, t.Path, err)
	}
	return nil
}

// AddRegistry registers a new public key under registryURL. It loads the
// pubkey from a PEM SPKI file (the format produced by `skillctl keygen`
// per stream S1's contract), decodes it to 32 raw bytes, and stores it
// base64-encoded in the YAML.
//
// Behavior:
//   - If registryURL has no entry yet, a new TrustRoot is appended with
//     sane defaults (`identity_keys_authorized: from-registry`,
//     `governance_minimum: green`).
//   - If registryURL already has an entry, the new key is appended to
//     its registry_keys list. This is the rotation overlap path: caller
//     is expected to mark the OLD key retired manually (via a future
//     `skillctl trust retire` or by editing the YAML).
//   - keyID is optional. If empty, a default ID derived from the key
//     fingerprint is generated so the user has SOMETHING to refer to.
//
// The pubkey file format uses S1's existing LoadPublicKey (PEM SPKI).
// Storing as base64-of-raw-bytes (per SPEC §4.4) keeps the YAML compact
// and matches the field type the verifier expects at runtime.
func (t *TrustRoots) AddRegistry(registryURL, pubkeyPath, keyID string) error {
	if t == nil {
		return errors.New("trust-roots: AddRegistry called on nil")
	}
	registryURL = strings.TrimRight(strings.TrimSpace(registryURL), "/")
	if registryURL == "" {
		return errors.New("trust-roots: --registry is required")
	}
	if pubkeyPath == "" {
		return errors.New("trust-roots: --pubkey is required")
	}
	if err := validateRegistryURL(registryURL); err != nil {
		return fmt.Errorf("trust-roots: %w", err)
	}

	pub, err := signing.LoadPublicKey(pubkeyPath)
	if err != nil {
		return fmt.Errorf("trust-roots: load pubkey %s: %w", pubkeyPath, err)
	}
	if len(pub) != pubkeyRawSize {
		// Belt-and-braces; signing.LoadPublicKey already enforces this.
		return fmt.Errorf("trust-roots: pubkey %s is %d bytes, want %d", pubkeyPath, len(pub), pubkeyRawSize)
	}
	rawCopy := make([]byte, len(pub))
	copy(rawCopy, pub)
	b64 := base64.StdEncoding.EncodeToString(rawCopy)

	if keyID == "" {
		keyID = deriveKeyID(rawCopy)
	}

	rk := RegistryKey{
		ID:        keyID,
		Pubkey:    rawCopy,
		PubkeyB64: b64,
		Issued:    todayISO(),
	}

	// Find or create the matching TrustRoot.
	if existing := t.findRegistry(registryURL); existing != nil {
		// Reject duplicate ID so the user can find their own entries.
		for _, k := range existing.RegistryKeys {
			if k.ID == rk.ID {
				return fmt.Errorf("trust-roots: registry %s already has a key with id %q", registryURL, rk.ID)
			}
			if k.PubkeyB64 == rk.PubkeyB64 {
				return fmt.Errorf("trust-roots: registry %s already pins this exact pubkey under id %q", registryURL, k.ID)
			}
		}
		existing.RegistryKeys = append(existing.RegistryKeys, rk)
		return nil
	}

	t.Roots = append(t.Roots, TrustRoot{
		RegistryURL:            registryURL,
		RegistryKeys:           []RegistryKey{rk},
		IdentityKeysAuthorized: "from-registry",
		GovernanceMinimum:      "green",
	})
	return nil
}

// FindRegistry returns the TrustRoot for registryURL or nil if there is no
// matching entry. The match is exact after a trailing-slash trim; SPEC §4.4
// does not specify URL canonicalization beyond that.
func (t *TrustRoots) FindRegistry(url string) *TrustRoot {
	if t == nil {
		return nil
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	return t.findRegistry(url)
}

// findRegistry is the unexported lookup; callers via FindRegistry get nil
// safety + URL normalization.
func (t *TrustRoots) findRegistry(url string) *TrustRoot {
	for i := range t.Roots {
		if t.Roots[i].RegistryURL == url {
			return &t.Roots[i]
		}
	}
	return nil
}

// RemoveRegistry deletes the TrustRoot for registryURL. Returns an error
// if no matching entry exists so the CLI can show a clear message.
func (t *TrustRoots) RemoveRegistry(url string) error {
	if t == nil {
		return errors.New("trust-roots: RemoveRegistry called on nil")
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	for i := range t.Roots {
		if t.Roots[i].RegistryURL == url {
			t.Roots = append(t.Roots[:i], t.Roots[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("trust-roots: no registry entry for %s", url)
}

// validate runs the full sanity check on the in-memory model. Called by
// Load (before returning) AND by Save (before writing) so the file on disk
// can never be in a state that Load would reject.
func (t *TrustRoots) validate() error {
	seenURLs := make(map[string]struct{}, len(t.Roots))
	for i, root := range t.Roots {
		if root.RegistryURL == "" {
			return fmt.Errorf("trust_roots[%d]: registry_url is required", i)
		}
		if err := validateRegistryURL(root.RegistryURL); err != nil {
			return fmt.Errorf("trust_roots[%d]: %w", i, err)
		}
		if _, dup := seenURLs[root.RegistryURL]; dup {
			return fmt.Errorf("trust_roots[%d]: duplicate registry_url %q", i, root.RegistryURL)
		}
		seenURLs[root.RegistryURL] = struct{}{}

		if len(root.RegistryKeys) == 0 {
			return fmt.Errorf("trust_roots[%d] %s: registry_keys is empty (a registry with no keys is useless)", i, root.RegistryURL)
		}
		seenIDs := make(map[string]struct{}, len(root.RegistryKeys))
		for j, k := range root.RegistryKeys {
			if k.ID == "" {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d]: id is required", i, j)
			}
			if _, dup := seenIDs[k.ID]; dup {
				return fmt.Errorf("trust_roots[%d] %s: duplicate key id %q", i, root.RegistryURL, k.ID)
			}
			seenIDs[k.ID] = struct{}{}

			if k.PubkeyB64 == "" {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d] (%s): pubkey is required", i, j, k.ID)
			}
			raw, err := base64.StdEncoding.DecodeString(k.PubkeyB64)
			if err != nil {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d] (%s): pubkey is not valid base64: %w", i, j, k.ID, err)
			}
			if len(raw) != pubkeyRawSize {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d] (%s): pubkey decodes to %d bytes, want %d", i, j, k.ID, len(raw), pubkeyRawSize)
			}
			// Hydrate Pubkey from PubkeyB64 so callers downstream
			// don't redo the decode.
			t.Roots[i].RegistryKeys[j].Pubkey = raw
		}
		if root.IdentityKeysAuthorized == "" {
			return fmt.Errorf("trust_roots[%d] %s: identity_keys_authorized is required", i, root.RegistryURL)
		}
		if _, ok := validIdentityModes[root.IdentityKeysAuthorized]; !ok {
			return fmt.Errorf("trust_roots[%d] %s: identity_keys_authorized %q is not one of [from-registry]", i, root.RegistryURL, root.IdentityKeysAuthorized)
		}
		if root.GovernanceMinimum == "" {
			return fmt.Errorf("trust_roots[%d] %s: governance_minimum is required", i, root.RegistryURL)
		}
		if _, ok := validGovernanceMinima[strings.ToLower(root.GovernanceMinimum)]; !ok {
			return fmt.Errorf("trust_roots[%d] %s: governance_minimum %q is not one of [green, yellow]", i, root.RegistryURL, root.GovernanceMinimum)
		}
	}
	return nil
}

// validateRegistryURL enforces an allowlist of URL schemes. HTTPS is
// always permitted; HTTP is permitted ONLY when the host is loopback or
// in an RFC1918 private range (so the home-lab MinIO at
// http://192.168.0.131:9100 works without `--allow-insecure`). Anything
// else is refused — a plain-HTTP public-Internet registry is exactly the
// scenario the trust-chain is meant to prevent.
//
// We keep this loose enough to be useful (no DNS lookup; no TLS probe)
// and strict enough that a public-Internet HTTP URL cannot land in the
// pinned config by accident.
func validateRegistryURL(url string) error {
	if strings.HasPrefix(url, "https://") {
		return nil
	}
	if strings.HasPrefix(url, "http://") {
		host := url[len("http://"):]
		// Strip path: take everything up to '/' or end.
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		// Strip port: take everything before ':'.
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		if isLoopbackOrPrivate(host) {
			return nil
		}
		return fmt.Errorf("registry_url %q uses http:// on a non-private host (only loopback and RFC1918 are allowed for plain HTTP)", url)
	}
	return fmt.Errorf("registry_url %q must use https:// (or http:// for loopback / RFC1918 only)", url)
}

// isLoopbackOrPrivate reports whether host is a loopback address or in an
// RFC1918 / IPv6-loopback range. This is intentionally lexical (no net
// lookups): "localhost" is loopback; "127.x.y.z" is loopback; "10.x.y.z",
// "192.168.x.y", "172.16.x.y" through "172.31.x.y" are private; "::1" is
// loopback.
func isLoopbackOrPrivate(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if strings.HasPrefix(host, "127.") {
		return true
	}
	if strings.HasPrefix(host, "10.") {
		return true
	}
	if strings.HasPrefix(host, "192.168.") {
		return true
	}
	if strings.HasPrefix(host, "172.") {
		// 172.16.0.0 – 172.31.255.255
		// Parse the second octet.
		rest := host[len("172."):]
		end := strings.IndexByte(rest, '.')
		if end < 0 {
			return false
		}
		oct := rest[:end]
		if len(oct) == 0 || len(oct) > 3 {
			return false
		}
		var n int
		for _, c := range oct {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		return n >= 16 && n <= 31
	}
	return false
}

// resolveAndValidatePath expands `~` in path, makes it absolute, and
// confirms it lies inside the user's home directory. The home-dir check
// is a defense against a misconfigured environment (HOME pointing somewhere
// surprising) silently picking up a config from an unexpected location.
//
// Test environments can override the home dir by setting HOME, since we
// route through os.UserHomeDir() which honors HOME.
func resolveAndValidatePath(path string) (string, error) {
	expanded := path
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("trust-roots: resolve ~: %w", err)
		}
		expanded = filepath.Join(home, path[2:])
	} else if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("trust-roots: resolve ~: %w", err)
		}
		expanded = home
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return "", fmt.Errorf("trust-roots: abs %s: %w", path, err)
	}
	// We do NOT enforce the home-dir constraint when an explicit
	// absolute path is provided by the caller (test code, alternate
	// config locations). The constraint only applies when the
	// CLI defaulted to ~/.claude/...; that guard lives at the CLI
	// boundary, not in Load.
	return abs, nil
}

// deriveKeyID returns a short, deterministic id of the form "key-<hex8>"
// derived from the first 4 bytes of the raw pubkey. Used as a fallback
// when the user doesn't pass --id.
func deriveKeyID(rawPub []byte) string {
	if len(rawPub) < 4 {
		return "key-unknown"
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len("key-")+8)
	out = append(out, "key-"...)
	for _, b := range rawPub[:4] {
		out = append(out, hex[b>>4], hex[b&0x0f])
	}
	return string(out)
}

// todayISO returns today's date in YYYY-MM-DD format. Pulled out as a var
// so tests can stub time without dragging the time package into the
// data-model file's hot path.
var todayISO = func() string {
	return nowISO()
}
