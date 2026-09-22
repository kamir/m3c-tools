package common

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file parses os-release(5), the Linux identity source of
// common.identity (SPEC-0471 TF06-R2).
//
// Mapping into OSInfo: one source key per field, no fallbacks, no defaults.
//
//	OSInfo.Name           NAME        ("Ubuntu", "Debian GNU/Linux")
//	OSInfo.Version        VERSION_ID  ("24.04", "12", "3.20.3")
//	OSInfo.Build          BUILD_ID    ("rolling"; most distributions omit it)
//	OSInfo.KernelRelease  never set here; the probe runs "uname -r"
//
// Not mapped: VERSION and PRETTY_NAME are display strings that embed the
// point release and a codename ("24.04.1 LTS (Noble Numbat)"), and ID is a
// lower-case machine id ("ubuntu"). Standing in for an absent NAME or
// VERSION_ID with one of them would mix representations, and a later diff
// would report a change that is only a change of source key. All keys stay
// available in OSReleaseData.Fields.
//
// An absent key leaves its field empty. The defaults os-release(5) allows a
// reader to assume ("NAME=Linux", "ID=linux") are not applied: a missing
// field is reported by the probe, never invented.

// os-release keys mapped into OSInfo.
const (
	osReleaseName      = "NAME"
	osReleaseVersionID = "VERSION_ID"
	osReleaseBuildID   = "BUILD_ID"
)

// Reasons of an OSReleaseIssue. They are stable strings.
const (
	OSReleaseIssueNotAssignment    = "not an assignment"
	OSReleaseIssueInvalidName      = "invalid variable name"
	OSReleaseIssueUnterminated     = "unterminated quote"
	OSReleaseIssueTextAfterQuote   = "text after closing quote"
	OSReleaseIssueShellExpansion   = "unescaped $ or backtick"
	OSReleaseIssueUnquotedBlank    = "unquoted value contains whitespace"
	OSReleaseIssueUnquotedSpecial  = "unquoted value contains a shell special character"
	OSReleaseIssueLineContinuation = "trailing backslash"
	OSReleaseIssueInvalidUTF8      = "value is not valid UTF-8"
	OSReleaseIssueNonPrintable     = "value contains a non-printable character"
)

// OSReleaseData is the complete parse of an os-release file.
type OSReleaseData struct {
	// Fields holds every well-formed assignment by variable name, values
	// exactly as assigned (quotes removed, escapes resolved, nothing
	// trimmed inside quotes). Names are case-sensitive. When a name is
	// assigned twice the later value wins, as in a shell.
	Fields map[string]string
	// Issues lists the malformed lines in file order.
	Issues []OSReleaseIssue
}

// OSReleaseIssue is a line that is neither blank, a comment nor a
// well-formed assignment. The line content is not kept, so an issue can go
// into a diagnostic as is; Line and Key locate it.
type OSReleaseIssue struct {
	// Line is the 1-based line number.
	Line int
	// Key is the variable name when the line assigns a valid name and only
	// the value is malformed, so a caller can tell a broken NAME from an
	// absent one. It is empty otherwise.
	Key string
	// Reason is one of the OSReleaseIssue* constants.
	Reason string
}

// Info maps the parsed fields into OSInfo (see the mapping above).
func (d OSReleaseData) Info() OSInfo {
	return OSInfo{
		Name:    d.Fields[osReleaseName],
		Version: d.Fields[osReleaseVersionID],
		Build:   d.Fields[osReleaseBuildID],
	}
}

// ParseOSRelease parses os-release(5) content and maps NAME, VERSION_ID and
// BUILD_ID into OSInfo (see the mapping at the top of this file). Content
// without any well-formed assignment is ErrNoFields. Well-formed content
// that assigns none of the three keys is not an error: the fields stay
// empty and the probe reports each one as missing.
func ParseOSRelease(b []byte) (OSInfo, error) {
	d, err := ParseOSReleaseData(b)
	if err != nil {
		return OSInfo{}, err
	}
	return d.Info(), nil
}

// ParseOSReleaseData parses os-release(5) content. The file is a list of
// shell-compatible variable assignments; this parser accepts the subset
// whose value a POSIX shell would assign without running anything, and
// reports every other line as an issue:
//
//   - One leading UTF-8 byte order mark is ignored. Lines end at "\n"; a
//     "\r" right before it is dropped, so CRLF input parses like LF input.
//   - Blank lines (spaces and tabs only) and lines whose first non-blank
//     character is "#" are ignored.
//   - An assignment is optional leading blanks, NAME=VALUE, optional
//     trailing blanks. NAME matches [A-Za-z_][A-Za-z0-9_]*; there are no
//     blanks around "=" ("KEY = v" and "export KEY=v" are issues).
//   - A double-quoted value resolves \\, \", \$ and \` to the second
//     character and keeps any other backslash, as a shell does. An
//     unescaped $ or backtick would be an expansion and is an issue.
//   - A single-quoted value is literal.
//   - An unquoted value resolves a backslash to the next character. A blank
//     inside it, a quote, $, backtick, one of ;&|<>(), or a tilde at the
//     start or after a colon (where a shell expands it) is an issue.
//   - After a closing quote only blanks may follow: concatenation and
//     inline comments are not part of os-release(5).
//   - A value must be valid UTF-8 without non-printable characters
//     (os-release(5)): control characters, format characters such as
//     bidirectional overrides, and line or paragraph separators are
//     issues. This also keeps terminal control sequences and display
//     spoofing out of attributes and reports.
//
// Each line is parsed on its own: an unterminated quote is an issue of its
// line and never swallows the lines after it. When no line is a well-formed
// assignment the result is ErrNoFields; the returned data is still valid
// and its Issues say why.
func ParseOSReleaseData(b []byte) (OSReleaseData, error) {
	d := OSReleaseData{Fields: map[string]string{}}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	for n := 1; len(b) > 0; n++ {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		key, value, reason, ok := parseOSReleaseLine(string(line))
		switch {
		case ok && key == "":
			// Blank line or comment.
		case ok:
			d.Fields[key] = value
		default:
			d.Issues = append(d.Issues, OSReleaseIssue{Line: n, Key: key, Reason: reason})
		}
	}
	if len(d.Fields) == 0 {
		return d, ErrNoFields
	}
	return d, nil
}

// parseOSReleaseLine parses one line without its terminator. ok with an
// empty key is a blank line or a comment. On failure key is set only when
// the name is valid and the value is malformed.
func parseOSReleaseLine(line string) (key, value, reason string, ok bool) {
	line = strings.TrimLeft(line, " \t")
	if line == "" || line[0] == '#' {
		return "", "", "", true
	}
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", OSReleaseIssueNotAssignment, false
	}
	name := line[:eq]
	if !isShellName(name) {
		return "", "", OSReleaseIssueInvalidName, false
	}
	value, reason = parseOSReleaseValue(line[eq+1:])
	if reason != "" {
		return name, "", reason, false
	}
	if !utf8.ValidString(value) {
		return name, "", OSReleaseIssueInvalidUTF8, false
	}
	if strings.IndexFunc(value, nonPrintable) >= 0 {
		return name, "", OSReleaseIssueNonPrintable, false
	}
	return name, value, "", true
}

// nonPrintable reports control (Cc), format (Cf) and line or paragraph
// separator (Zl, Zp) characters.
func nonPrintable(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// isShellName accepts [A-Za-z_][A-Za-z0-9_]*, a POSIX shell variable name.
func isShellName(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// parseOSReleaseValue parses the text after "=". A non-empty reason means
// the value is malformed.
func parseOSReleaseValue(s string) (string, string) {
	var sb strings.Builder
	var rest string
	switch {
	case s == "":
		return "", ""
	case s[0] == '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", OSReleaseIssueUnterminated
		}
		sb.WriteString(s[1 : 1+end])
		rest = s[2+end:]
	case s[0] == '"':
		i := 1
		for {
			if i >= len(s) {
				return "", OSReleaseIssueUnterminated
			}
			c := s[i]
			if c == '"' {
				break
			}
			switch c {
			case '\\':
				if i+1 >= len(s) {
					// A backslash before the line end continues the
					// quoted string on the next line: not supported.
					return "", OSReleaseIssueUnterminated
				}
				if strings.IndexByte("\\\"$`", s[i+1]) >= 0 {
					sb.WriteByte(s[i+1])
					i += 2
					continue
				}
				sb.WriteByte(c)
			case '$', '`':
				return "", OSReleaseIssueShellExpansion
			default:
				sb.WriteByte(c)
			}
			i++
		}
		rest = s[i+1:]
	default:
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case c == ' ' || c == '\t':
				if strings.TrimLeft(s[i:], " \t") != "" {
					return "", OSReleaseIssueUnquotedBlank
				}
				return sb.String(), ""
			case c == '\\':
				if i+1 >= len(s) {
					return "", OSReleaseIssueLineContinuation
				}
				i++
				sb.WriteByte(s[i])
			case c == '$' || c == '`':
				return "", OSReleaseIssueShellExpansion
			case strings.IndexByte("\"';&|<>()", c) >= 0:
				return "", OSReleaseIssueUnquotedSpecial
			case c == '~' && (i == 0 || s[i-1] == ':'):
				// Tilde expansion applies at the start of an assignment
				// value and after each unquoted colon.
				return "", OSReleaseIssueUnquotedSpecial
			default:
				sb.WriteByte(c)
			}
		}
		return sb.String(), ""
	}
	if strings.TrimLeft(rest, " \t") != "" {
		return "", OSReleaseIssueTextAfterQuote
	}
	return sb.String(), ""
}
