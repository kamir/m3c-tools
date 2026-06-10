package main

// verdict_cache.go — offline verdict cache (SPEC-0247 P1.1, §8).
//
// The online §7 chain (VerifyInstalled) fetches fresh registry metadata, so
// running it on every PreToolUse(Skill) invocation is slow and network-bound.
// The cache breaks that: the SessionStart sweep (and the first hook miss) run
// the chain ONCE and record a signed verdict keyed on the installed skill's
// CONTENT digest; subsequent invocations read the cache offline.
//
// Tamper-evidence (§8 R-8.2): the key is the content digest of the on-disk
// skill dir. Editing any installed file changes the digest → the cached PASS no
// longer matches → cache miss → fail-closed re-verify. Forging a cache row is
// useless without also producing files whose digest matches that row, which the
// honest verifier would never have signed PASS. The HMAC (key at
// ~/.claude/skillctl/verdict.key, 0600) only stops casual tampering / stale
// rows — it is explicitly NOT the trust boundary (that's the binary + trust
// roots + §3.2).
//
// Offline resilience: when the registry is unreachable, an unexpired PASS row
// for an UNCHANGED skill still allows it (we verified it recently and the bytes
// haven't moved) — see verify_all_cmds.go, which leaves the row in place on an
// availability failure instead of deleting it.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// verdictTTLSeconds is how long a recorded PASS stays usable. The sweep
// refreshes rows every SessionStart, so this only matters within a long-running
// session or across an offline stretch. 12h comfortably covers a work session.
const verdictTTLSeconds = 12 * 3600

// verdictMaxDigestBytes caps how much we hash to key the cache. Managed skills
// are small (SKILL.md + a .skb); above the cap we skip caching (always online)
// rather than pay a per-invocation hashing cost.
const verdictMaxDigestBytes = 16 << 20 // 16 MiB

type verdictEntry struct {
	Name         string `json:"name"`
	Digest       string `json:"digest"` // content digest of the installed dir
	Verdict      string `json:"verdict"`
	Exit         int    `json:"exit"`
	ChainSummary string `json:"chain_summary,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	CheckedAt    string `json:"checked_at"`
	TTLSeconds   int    `json:"ttl_seconds"`
	Online       bool   `json:"online"`
	HMAC         string `json:"hmac"`
}

type verdictCache struct {
	Version int            `json:"version"`
	Entries []verdictEntry `json:"entries"`
}

func verdictDir(home string) string       { return filepath.Join(home, ".claude", "skillctl") }
func verdictCachePath(home string) string { return filepath.Join(verdictDir(home), "verdicts.json") }
func verdictKeyPath(home string) string   { return filepath.Join(verdictDir(home), "verdict.key") }

// loadOrCreateVerdictKey returns the 32-byte HMAC key, generating it (0600) on
// first use.
func loadOrCreateVerdictKey(home string) ([]byte, error) {
	p := verdictKeyPath(home)
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b[:32], nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func loadVerdictCache(home string) verdictCache {
	c := verdictCache{Version: 1}
	if b, err := os.ReadFile(verdictCachePath(home)); err == nil {
		_ = json.Unmarshal(b, &c) // a corrupt cache degrades to "empty" → re-verify
	}
	return c
}

func saveVerdictCache(home string, c verdictCache) {
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	c.Version = 1
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	// Use a UNIQUE temp file per write (SPEC-0251 VERDICT-CACHE TMP RACE): a
	// fixed "verdicts.json.tmp" lets two concurrent gate invocations (a
	// SessionStart sweep and a PreToolUse hook, say) write the SAME temp path and
	// rename it out from under each other, corrupting the cache. os.CreateTemp
	// gives each writer its own file in the same dir (so the rename stays atomic
	// on one filesystem); last-writer-wins on the final rename is fine — a lost
	// race just yields a future cache miss → re-verify.
	f, err := os.CreateTemp(dir, "verdicts-*.json")
	if err != nil {
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename; cleans up on any error
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return
	}
	if err := f.Close(); err != nil {
		return
	}
	_ = os.Rename(tmp, verdictCachePath(home)) // atomic publish
}

// signVerdict / validVerdict bind a row to the HMAC key over its canonical
// fields (everything that matters for the decision).
func signVerdict(key []byte, e verdictEntry) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s|%s|%s|%d|%s|%s|%d|%t",
		e.Name, e.Digest, e.Verdict, e.Exit, e.SessionID, e.CheckedAt, e.TTLSeconds, e.Online)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func validVerdict(key []byte, e verdictEntry) bool {
	return hmac.Equal([]byte(signVerdict(key, e)), []byte(e.HMAC))
}

func verdictFresh(e verdictEntry, now time.Time) bool {
	if e.TTLSeconds <= 0 {
		return false
	}
	t, err := time.Parse(time.RFC3339, e.CheckedAt)
	if err != nil {
		return false
	}
	return now.Before(t.Add(time.Duration(e.TTLSeconds) * time.Second))
}

// computeInstalledDigest is a deterministic content digest over every regular
// file in the installed skill dir (sorted relpath + length-prefixed bytes), so
// ANY edit to ANY file changes it. .DS_Store is ignored. Returns "" (no error
// path used by callers) when the dir is missing or exceeds the size cap.
func computeInstalledDigest(dir string) (string, error) {
	var files []string
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == ".DS_Store" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > verdictMaxDigestBytes {
			return fmt.Errorf("skill dir exceeds digest cap")
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		io.WriteString(h, rel)
		h.Write([]byte{0})
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		var lb [8]byte
		binary.BigEndian.PutUint64(lb[:], uint64(len(b)))
		h.Write(lb[:])
		h.Write(b)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// cachedAllow reports whether a fresh, valid, digest-matching PASS row exists
// for <name> — i.e. the gate can allow offline without re-running the chain.
func cachedAllow(home, name, sessionID string, now time.Time) bool {
	digest, err := computeInstalledDigest(filepath.Join(home, ".claude", "skills", name))
	if err != nil || digest == "" {
		return false
	}
	key, err := loadOrCreateVerdictKey(home)
	if err != nil {
		return false
	}
	for _, e := range loadVerdictCache(home).Entries {
		if e.Name != name || e.Digest != digest || e.Verdict != "pass" {
			continue
		}
		if !validVerdict(key, e) || !verdictFresh(e, now) {
			continue
		}
		// Optional session binding: a row stamped with a different session is
		// ignored (the sweep stamps "" → matches any session, TTL bounds it).
		if e.SessionID != "" && sessionID != "" && e.SessionID != sessionID {
			continue
		}
		return true
	}
	return false
}

// recordVerdict updates the cache after an online managed verify: a PASS writes
// a fresh signed row; any non-PASS removes the skill's row (so a now-failing
// skill cannot ride an old PASS). A best-effort, last-writer-wins file update —
// a lost race just yields a future cache miss → re-verify.
func recordVerdict(home, name, sessionID string, code int, summary string, now time.Time) {
	key, err := loadOrCreateVerdictKey(home)
	if err != nil {
		return
	}
	c := loadVerdictCache(home)
	kept := c.Entries[:0]
	for _, e := range c.Entries {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	c.Entries = kept
	if code == exitOK {
		if digest, err := computeInstalledDigest(filepath.Join(home, ".claude", "skills", name)); err == nil && digest != "" {
			e := verdictEntry{
				Name: name, Digest: digest, Verdict: "pass", Exit: 0,
				ChainSummary: summary, SessionID: sessionID,
				CheckedAt: now.UTC().Format(time.RFC3339), TTLSeconds: verdictTTLSeconds, Online: true,
			}
			e.HMAC = signVerdict(key, e)
			c.Entries = append(c.Entries, e)
		}
	}
	saveVerdictCache(home, c)
}
