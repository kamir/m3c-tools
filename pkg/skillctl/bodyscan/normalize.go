package bodyscan

import (
	"strings"
	"unicode/utf8"
)

// normalized holds the result of canonicalising a body for regex matching while
// preserving a mapping back to the ORIGINAL byte offsets.
//
// SPEC-0246 §4: adversaries hide injection prose by inserting default-ignorable
// / zero-width code points ("ig<soft-hyphen>nore"), by using
// fullwidth Latin (fullwidth Latin "ignore"), and by other Unicode
// tricks that survive an LLM's tokeniser but defeat a naive ASCII regex. We
// therefore match against a folded copy of the body, but every finding span must
// point back into the bytes the user can see, so the report excerpt and line
// number stay meaningful.
type normalized struct {
	// Text is the folded body the rules run against.
	Text string
	// offsets maps a byte index in Text to the corresponding byte index in the
	// original body. It has len(Text)+1 entries so that a span End (exclusive)
	// can always be mapped, including End == len(Text).
	offsets []int
	// Changed is true when folding altered the text (a zero-width strip or a
	// fullwidth fold happened) — an obfuscation signal in its own right.
	Changed bool
}

// origStart maps a normalized start byte index back to the original body.
func (n *normalized) origStart(i int) int {
	if i < 0 {
		return 0
	}
	if i >= len(n.offsets) {
		return n.offsets[len(n.offsets)-1]
	}
	return n.offsets[i]
}

// origEnd maps a normalized end byte index (exclusive) back to the original
// body. We use the offset stored at the index itself so the original span ends
// just before the next surviving original byte.
func (n *normalized) origEnd(i int) int {
	if i < 0 {
		return 0
	}
	if i >= len(n.offsets) {
		return n.offsets[len(n.offsets)-1]
	}
	return n.offsets[i]
}

// Default-ignorable / zero-width code points stripped before matching. Written
// as numeric escapes so the source file stays plain ASCII (no invisible bytes).
const (
	runeSoftHyphen   = rune(0x00AD) // SOFT HYPHEN
	runeZWSpace      = rune(0x200B) // ZERO WIDTH SPACE
	runeZWNonJoiner  = rune(0x200C) // ZERO WIDTH NON-JOINER
	runeZWJoiner     = rune(0x200D) // ZERO WIDTH JOINER
	runeWordJoiner   = rune(0x2060) // WORD JOINER
	runeBOM          = rune(0xFEFF) // ZERO WIDTH NO-BREAK SPACE / BOM
	runeVarSelStart  = rune(0xFE00) // VARIATION SELECTOR-1
	runeVarSelEnd    = rune(0xFE0F) // VARIATION SELECTOR-16
	runeFullwidthLo  = rune(0xFF01) // FULLWIDTH EXCLAMATION MARK
	runeFullwidthHi  = rune(0xFF5E) // FULLWIDTH TILDE
	fullwidthToASCII = rune(0xFEE0) // U+FF01..U+FF5E minus this == U+0021..U+007E
)

// isIgnorable reports whether r is a default-ignorable / zero-width code point
// we strip before matching. This is a targeted stdlib fold (no x/text): it
// covers the demonstrated evasions — zero-width space/joiners, BOM/word-joiner,
// and the soft hyphen — without pulling in a Unicode-tables dependency.
func isIgnorable(r rune) bool {
	switch r {
	case runeSoftHyphen, runeZWSpace, runeZWNonJoiner, runeZWJoiner, runeWordJoiner, runeBOM:
		return true
	}
	if r >= runeVarSelStart && r <= runeVarSelEnd {
		return true
	}
	return false
}

// foldRune maps a single rune to its canonical ASCII form for matching, or
// returns drop=true when the rune should be dropped entirely (ignorable). The
// returned rune may equal r (no change). For fullwidth ASCII (U+FF01..U+FF5E) it
// folds to the corresponding ASCII (U+0021..U+007E) by subtracting 0xFEE0.
func foldRune(r rune) (folded rune, drop bool) {
	if isIgnorable(r) {
		return 0, true
	}
	if r >= runeFullwidthLo && r <= runeFullwidthHi {
		return r - fullwidthToASCII, false
	}
	return r, false
}

// normalizeBody folds body for matching and records the offset map back to the
// original bytes. Stripped (ignorable) runes leave a "hole" — the next
// surviving normalized byte maps to the original index just past the stripped
// rune — so adjacent characters re-join (defeating soft-hyphen / zero-width
// splitting) while every surviving byte still resolves to a real original
// offset.
func normalizeBody(body string) *normalized {
	// Fast path: plain ASCII with no escape sequences and no spaced-letter runs
	// needs no transformation at all (overwhelmingly the common case).
	if isPlainASCII(body) && !mightNeedDecode(body) {
		offsets := make([]int, len(body)+1)
		for i := range offsets {
			offsets[i] = i
		}
		return &normalized{Text: body, offsets: offsets, Changed: false}
	}

	var sb strings.Builder
	sb.Grow(len(body))
	offsets := make([]int, 0, len(body)+1)
	changed := false

	emit := func(r rune, origIdx int) {
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], r)
		for k := 0; k < n; k++ {
			offsets = append(offsets, origIdx)
			sb.WriteByte(buf[k])
		}
	}

	for i := 0; i < len(body); {
		// \uXXXX / \xXX escape decoding (SPEC-0246 §4, evasion: "\uNNNN-encoded").
		if r, consumed, ok := decodeEscape(body[i:]); ok {
			folded, drop := foldRune(r)
			changed = true
			if !drop {
				emit(folded, i)
			}
			i += consumed
			continue
		}
		r, size := utf8.DecodeRuneInString(body[i:])
		folded, drop := foldRune(r)
		if drop {
			changed = true
			i += size
			continue
		}
		if folded != r {
			changed = true
		}
		emit(folded, i)
		i += size
	}
	offsets = append(offsets, len(body)) // sentinel for End == len(Text)

	text, offsets, despaced := collapseSpacedLetters(sb.String(), offsets)
	if despaced {
		changed = true
	}

	return &normalized{Text: text, offsets: offsets, Changed: changed}
}

// mightNeedDecode reports whether body contains constructs that the slow path
// must handle even though the body is plain ASCII: backslash-u/x escapes, or a
// run of single letters separated by single spaces (letter-spacing evasion).
func mightNeedDecode(body string) bool {
	if strings.Contains(body, `\u`) || strings.Contains(body, `\x`) {
		return true
	}
	return hasSpacedLetterRun(body)
}

// decodeEscape decodes a leading \uXXXX (4 hex) or \xXX (2 hex) escape in s.
// It returns the decoded rune, the number of source bytes consumed, and ok.
func decodeEscape(s string) (r rune, consumed int, ok bool) {
	if len(s) >= 6 && s[0] == '\\' && (s[1] == 'u' || s[1] == 'U') {
		if v, good := parseHex(s[2:6]); good {
			return rune(v), 6, true
		}
	}
	if len(s) >= 4 && s[0] == '\\' && (s[1] == 'x' || s[1] == 'X') {
		if v, good := parseHex(s[2:4]); good {
			return rune(v), 4, true
		}
	}
	return 0, 0, false
}

// parseHex parses exactly len(h) hex digits into an int.
func parseHex(h string) (int, bool) {
	v := 0
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v*16 + int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// minSpacedLetters is how many single letters separated by single spaces must
// appear in a row before we treat it as a letter-spacing evasion and collapse
// the interior spaces. Set high enough that ordinary short tokens ("a b") are
// untouched.
const minSpacedLetters = 4

// hasSpacedLetterRun reports whether s contains a run of >= minSpacedLetters
// single ASCII letters each separated by a single space ("I g n o r e").
func hasSpacedLetterRun(s string) bool {
	run := 0
	i := 0
	for i < len(s) {
		// Need: letter at i, space at i+1, letter at i+2 ...
		if isASCIILetter(s[i]) {
			run++
			if run >= minSpacedLetters {
				return true
			}
			if i+1 < len(s) && s[i+1] == ' ' && i+2 < len(s) && isASCIILetter(s[i+2]) {
				i += 2
				continue
			}
			run = 0
			i++
			continue
		}
		run = 0
		i++
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// collapseSpacedLetters removes the single interior spaces from runs of
// >= minSpacedLetters single letters separated by single spaces ("I g n o r e"
// -> "Ignore"), keeping the offset map consistent. It returns the new text, the
// new offset slice, and whether anything changed.
func collapseSpacedLetters(text string, offsets []int) (string, []int, bool) {
	if !hasSpacedLetterRun(text) {
		return text, offsets, false
	}
	var sb strings.Builder
	sb.Grow(len(text))
	newOffsets := make([]int, 0, len(offsets))

	n := len(text)
	i := 0
	changed := false
	for i < n {
		// Detect the start of a spaced-letter run at i.
		if isASCIILetter(text[i]) {
			runLen := spacedRunLength(text, i)
			if runLen >= minSpacedLetters {
				// Emit the letters, dropping the interior single spaces.
				j := i
				for k := 0; k < runLen; k++ {
					sb.WriteByte(text[j])
					newOffsets = append(newOffsets, offsets[j])
					j++ // letter
					if k < runLen-1 {
						j++ // skip the single space
					}
				}
				changed = true
				i = j
				continue
			}
		}
		sb.WriteByte(text[i])
		newOffsets = append(newOffsets, offsets[i])
		i++
	}
	newOffsets = append(newOffsets, offsets[len(offsets)-1])
	return sb.String(), newOffsets, changed
}

// spacedRunLength returns how many single letters separated by single spaces
// start at index i in text.
func spacedRunLength(text string, i int) int {
	count := 0
	n := len(text)
	for i < n && isASCIILetter(text[i]) {
		count++
		// Is the next thing " <letter>"?
		if i+2 < n && text[i+1] == ' ' && isASCIILetter(text[i+2]) {
			// But stop if i+3 is also a letter (i.e. the "letter" at i+2 is part
			// of a multi-letter word, not a single spaced letter) UNLESS it is
			// the final letter. We require strict single-letter tokens.
			if i+3 < n && isASCIILetter(text[i+3]) {
				break
			}
			i += 2
			continue
		}
		break
	}
	return count
}

// isPlainASCII reports whether s contains only bytes < 0x80 (so no folding or
// stripping can apply).
func isPlainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
