package registry

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pjbgf/sha1cd"
)

type nativeGitEntry struct{ name, mode, kind, oid string }

func nativeGitName(name string) bool {
	return len(name) > 0 && len(name) <= 4096 && utf8.ValidString(name) && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

func nativeGitVerifyObject(kind string, raw []byte, expected string, work *nativeLiveWork) error {
	if !nativeGitOID(expected) || (kind != "blob" && kind != "tree") {
		return ErrNativeEvidenceInvalid
	}
	if err := work.charge(int64(len(raw)) + 128); err != nil {
		return err
	}
	// A fresh complete framed hash preserves collision indication. Never marshal
	// hash state, use ordinary hash.Hash.Sum, or silently fall back to crypto/sha1.
	h, ok := sha1cd.New().(sha1cd.CollisionResistantHash)
	if !ok {
		return ErrNativeEvidenceInvalid
	}
	if _, err := fmt.Fprintf(h, "%s %d%c", kind, len(raw), byte(0)); err != nil {
		return ErrNativeEvidenceInvalid
	}
	if _, err := h.Write(raw); err != nil {
		return ErrNativeEvidenceInvalid
	}
	sum, collision := h.CollisionResistantSum(nil)
	return nativeGitCompareHash(sum, collision, expected)
}

func nativeGitCompareHash(sum []byte, collision bool, expected string) error {
	if collision || hex.EncodeToString(sum) != expected {
		return ErrNativeEvidenceInvalid
	}
	return nil
}

// Git compares a directory basename with a virtual trailing slash, and a
// regular entry with NUL. No key is allocated by the sort comparator.
func nativeGitEntryLess(a, b nativeGitEntry) bool {
	i := 0
	for i < len(a.name) && i < len(b.name) {
		if a.name[i] != b.name[i] {
			return a.name[i] < b.name[i]
		}
		i++
	}
	var ac, bc byte
	if i < len(a.name) {
		ac = a.name[i]
	} else if a.kind == "tree" {
		ac = '/'
	}
	if i < len(b.name) {
		bc = b.name[i]
	} else if b.kind == "tree" {
		bc = '/'
	}
	return ac < bc
}
func (f *nativeGitFetch) reserveEntryPath(path, name string) error {
	n := len(name)
	if path != "" {
		n += len(path) + 1
	}
	if n > 4096 || n > 4<<20-f.pathBytes {
		return ErrNativeEvidenceInvalid
	}
	if err := f.work.charge(4*int64(n) + 256); err != nil {
		return err
	}
	f.pathBytes += n
	return nil
}
func nativeGitTreeBytes(entries []nativeGitEntry, work *nativeLiveWork) ([]byte, error) {
	size := 0
	for _, entry := range entries {
		size += len(entry.mode) + 1 + len(entry.name) + 1 + 20
	}
	if err := work.charge(2*int64(size) + int64(len(entries))*128); err != nil {
		return nil, err
	}
	ordered := append([]nativeGitEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return nativeGitEntryLess(ordered[i], ordered[j]) })
	raw := make([]byte, 0, size)
	for _, entry := range ordered {
		mode := entry.mode
		if mode == "040000" {
			mode = "40000"
		}
		oid, e := hex.DecodeString(entry.oid)
		if e != nil || len(oid) != 20 {
			return nil, ErrNativeEvidenceInvalid
		}
		raw = append(raw, mode...)
		raw = append(raw, ' ')
		raw = append(raw, entry.name...)
		raw = append(raw, 0)
		raw = append(raw, oid...)
	}
	return raw, nil
}
func (f *nativeGitFetch) decodeEntries(v any, path string) ([]nativeGitEntry, error) {
	values, ok := v.([]any)
	if !ok || len(values) > nativeGitEntriesMax-f.treeEntries {
		return nil, ErrNativeEvidenceInvalid
	}
	if err := f.work.charge(int64(len(values)) * 256); err != nil {
		return nil, err
	}
	f.treeEntries += len(values)
	result := make([]nativeGitEntry, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		var m map[string]any
		var err error
		var entry nativeGitEntry
		if f.source.provider == "github" {
			m, err = nativeGitMap(v, []string{"path", "mode", "type", "sha"}, "size", "url")
			if err == nil {
				entry.name, _ = m["path"].(string)
				entry.oid, _ = m["sha"].(string)
			}
		} else {
			m, err = nativeGitMap(v, []string{"name", "mode", "type", "id", "path"})
			if err == nil {
				entry.name, _ = m["name"].(string)
				entry.oid, _ = m["id"].(string)

			}
		}
		if err != nil {
			return nil, err
		}
		entry.mode, _ = m["mode"].(string)
		entry.kind, _ = m["type"].(string)
		if !nativeGitName(entry.name) || !nativeGitOID(entry.oid) || seen[entry.name] {
			return nil, ErrNativeEvidenceInvalid
		}
		if err = f.reserveEntryPath(path, entry.name); err != nil {
			return nil, err
		}
		if f.source.provider == "gitlab" {
			expected := entry.name
			if path != "" {
				expected = path + "/" + entry.name
			}
			if m["path"] != expected {
				return nil, ErrNativeEvidenceInvalid
			}
		}

		switch entry.mode {
		case "040000":
			if entry.kind != "tree" {
				return nil, ErrNativeEvidenceInvalid
			}
		case "100644", "100755", "120000":
			if entry.kind != "blob" {
				return nil, ErrNativeEvidenceInvalid
			}
		case "160000":
			if entry.kind != "commit" {
				return nil, ErrNativeEvidenceInvalid
			}
		default:
			return nil, ErrNativeEvidenceInvalid
		}
		if size, exists := m["size"]; exists {
			if _, err = nativeGitInteger(size, nativeGitResponsesMax); err != nil {
				return nil, err
			}
		}
		seen[entry.name] = true
		result = append(result, entry)
	}
	return result, nil
}
func nativeGitPage(h http.Header, page int, count int) error {
	if len(h.Values("X-Next-Page")) > 1 || len(h.Values("X-Page")) > 1 {
		return ErrNativeEvidenceInvalid
	}
	if current := h.Get("X-Page"); current != "" && current != strconv.Itoa(page) {
		return ErrNativeEvidenceInvalid
	}
	next := h.Get("X-Next-Page")
	if next != "" && (next != strconv.Itoa(page+1) || count != 100) {
		return ErrNativeEvidenceInvalid
	}
	// We construct the next fixed query ourselves. No Link URL is a capability.
	if count < 100 && next != "" {
		return ErrNativeEvidenceInvalid
	}
	return nil
}
func (f *nativeGitFetch) treeAt(path, expected string) ([]nativeGitEntry, error) {
	if prior, ok := f.verifiedPaths[path]; ok {
		if prior != expected {
			return nil, ErrNativeEvidenceInvalid
		}
		return f.trees[expected], nil
	}
	if cached, ok := f.trees[expected]; ok {
		if len(cached) > nativeGitEntriesMax-f.treeEntries {
			return nil, ErrNativeEvidenceInvalid
		}
		if err := f.work.charge(256); err != nil {
			return nil, err
		}
		for _, entry := range cached {
			if err := f.reserveEntryPath(path, entry.name); err != nil {
				return nil, err
			}
		}
		f.treeEntries += len(cached)
		f.verifiedPaths[path] = expected
		return cached, nil
	}
	if err := f.object(expected); err != nil {
		return nil, err
	}
	var entries []nativeGitEntry
	if f.source.provider == "github" {
		v, _, err := f.json(f.apiPath("/git/trees/"+expected), nativeGitMetadataMax)
		if err != nil {
			return nil, err
		}
		m, err := nativeGitMap(v, []string{"sha", "tree", "truncated"}, "url")
		if err != nil || m["sha"] != expected || m["truncated"] != false {
			return nil, ErrNativeEvidenceInvalid
		}
		entries, err = f.decodeEntries(m["tree"], path)
		if err != nil {
			return nil, err
		}
	} else {
		seen := map[string]bool{}
		for page := 1; ; page++ {
			if page > 42 {
				return nil, ErrNativeEvidenceInvalid
			}
			query := url.Values{"ref": {f.source.commit}, "recursive": {"false"}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
			if path != "" {
				query.Set("path", path)
			}
			v, h, err := f.json(f.apiPath("/tree")+"?"+query.Encode(), nativeGitMetadataMax)
			if err != nil {
				return nil, err
			}
			part, err := f.decodeEntries(v, path)
			if err != nil || len(part) > 100 || nativeGitPage(h, page, len(part)) != nil {
				return nil, ErrNativeEvidenceInvalid
			}
			if len(part) > nativeGitEntriesMax-len(entries) {
				return nil, ErrNativeEvidenceInvalid
			}
			for _, entry := range part {
				if seen[entry.name] {
					return nil, ErrNativeEvidenceInvalid
				}
				seen[entry.name] = true
				entries = append(entries, entry)
			}
			if len(part) < 100 {
				break
			}
		}
	}
	raw, err := nativeGitTreeBytes(entries, &f.work)
	if err != nil {
		return nil, err
	}
	if err = nativeGitVerifyObject("tree", raw, expected, &f.work); err != nil {
		return nil, err
	}
	if err = f.work.charge(256); err != nil {
		return nil, err
	}
	f.trees[expected] = entries
	f.verifiedPaths[path] = expected
	return entries, nil
}
func (f *nativeGitFetch) pathCharge(path string) error {
	if len(path) > 4096 || f.entries >= nativeGitEntriesMax {
		return ErrNativeEvidenceInvalid
	}
	if err := f.work.charge(int64(128)); err != nil {
		return err
	}
	f.entries++
	return nil
}
func (f *nativeGitFetch) lookup(parts []string) (nativeGitEntry, error) {
	oid, path := f.source.tree, ""
	for i, name := range parts {
		if !nativeGitName(name) {
			return nativeGitEntry{}, ErrNativeEvidenceInvalid
		}
		entries, err := f.treeAt(path, oid)
		if err != nil {
			return nativeGitEntry{}, err
		}
		var found *nativeGitEntry
		for index := range entries {
			if entries[index].name == name {
				found = &entries[index]
				break
			}
		}
		if found == nil {
			return nativeGitEntry{}, ErrNativeEvidenceInvalid
		}
		if i == len(parts)-1 {
			return *found, nil
		}
		if found.kind != "tree" || found.mode != "040000" {
			return nativeGitEntry{}, ErrNativeEvidenceInvalid
		}
		if path != "" {
			path += "/"
		}
		path += name
		oid = found.oid
	}
	return nativeGitEntry{}, ErrNativeEvidenceInvalid
}
func (f *nativeGitFetch) bundleBlob(name, version string) ([]byte, error) {
	if !validAgentName(name) || !agentText(version, 256) || strings.ContainsAny(version, "/\\\x00") || version == "." || version == ".." {
		return nil, ErrNativeEvidenceInvalid
	}
	entry, err := f.lookup([]string{"skills", name, version, "bundle.skb"})
	if err != nil {
		return nil, err
	}
	if entry.kind != "blob" || (entry.mode != "100644" && entry.mode != "100755") {
		return nil, ErrNativeEvidenceInvalid
	}
	return f.blob(entry.oid, nativeGitArchiveMax)
}

// nativeGitJSON rejects lossy surrogate decoding before the shared bounded
// unique/canonical-key decoder materializes any map.
func nativeGitJSON(raw []byte, limit int, secret string, work *nativeLiveWork) (any, error) {
	if !nativeGitScalarEscapes(raw) {
		return nil, ErrNativeEvidenceInvalid
	}
	return nativeLiveJSON(raw, limit, secret, work)
}
func nativeGitScalarEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
