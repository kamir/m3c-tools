package linux

// linux.executables (SPEC-0471 TF06-R3) reports the PROGRAMS behind the
// services and the listening sockets of this host, each with the SHA-256 of
// the bytes that are on disk right now.
//
// Why a separate probe. linux.systemd records that a unit starts
// /usr/local/bin/ngrok; linux.network.listeners records that something listens
// on every address. Neither can say whether the program is still the same
// program. A baseline that cannot answer that is half a baseline: the unit file
// is unchanged, the listener is unchanged, and the binary behind them was
// replaced last night.
//
// Where the paths come from, and nothing else:
//
//   - every ExecStart path of the units SelectUnitsForShow picks, read through
//     the same "systemctl show" call linux.systemd makes (with a two property
//     list, because only Id and ExecStart are needed here);
//   - the executable behind a listening socket, where the owning process is
//     observable: "ss -H -lntup" names the pid, and /proc/<pid>/exe is the
//     kernel's answer for the program behind it. Unprivileged that link is
//     readable for the caller's own processes only, so the usual result is a
//     handful of programs and a named gap for the rest (playbook L1).
//
// No host, product or unit name appears anywhere in this file (T-03b B1): ngrok
// and MinIO are found because a unit names a program and a socket has an owner,
// or they are not found at all.
//
// What bounds the answer (T-03b B3), because hashing is the one operation here
// that can cost real time and real memory if it is unbounded:
//
//   - an allowlist of roots (ExecutableRoots): /usr, /bin, /sbin, /opt, /snap
//     and /usr/local. No file OUTSIDE them is opened. The one path this probe
//     touches outside the roots is /proc/<pid>/exe, and it is not opened: it is
//     read as a link (a readlink through ProgramReader.ProcessExecutable) to
//     learn the program name of a listening process, and the target is then
//     subject to the same root rules as every other candidate;
//   - never a path under a home directory (ExecutableHomePrefixes), not even
//     when a symlink inside the roots points there;
//   - ExecutableMaxCandidates per capture BEFORE anything is resolved,
//     ExecutableMaxFileBytes per file and ExecutableMaxFiles per capture;
//   - every refusal, every limit and every unreadable file is its own
//     diagnostic that names the file and the cause, and the probe is then
//     partial. A capture that hashed 200 of 260 programs says so.
//
// A program that no package owns is a FINDING and not an error (T-03b B4): it
// is recorded with package_owner "none" and the way that was determined. The
// trust judgement belongs to the policy, never to a probe.
//
// What is observed here and what is a database's claim. The artifact State is
// observed, and for path, size, mode, owner, group and sha256 that is exactly
// what it is: this probe read them off the file system of this host. Two
// attributes are NOT observations of the file: package_owner and diverted_by
// are what the package database answers ABOUT the path, recorded beside the
// digest because a program nobody owns is the finding a bastion is captured
// for. package_owner_source names which answer it is (dpkg, dpkg_no_match,
// snap_path, dpkg_unavailable). This build never verifies a file against its
// package (no "dpkg --verify", no recorded package digest), so an owned path
// is not a statement that the bytes on disk are the package's bytes; the
// sha256 beside it is the only statement about the bytes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// Probe identity and the executables it runs.
const (
	// ExecutablesProbeID is the probe id.
	ExecutablesProbeID = "linux.executables"
	// ExecutablesProbeVersion changes whenever the output of the probe can
	// change.
	ExecutablesProbeVersion = "1"
	// ExecutablesToolStat reads mode, owner, group and size of a file.
	ExecutablesToolStat = "stat"
	// ExecutablesToolDpkg answers which package owns a path ("dpkg -S").
	ExecutablesToolDpkg = "dpkg"
)

// Artifact ids of this probe. One artifact per program file, plus one set
// artifact that states the result even when there is no program to record.
const (
	// ArtifactExecutablePrefix prefixes one program file; the resolved path
	// follows without its leading slash and with the characters an artifact id
	// may not carry replaced (ExecutableArtifactID). The raw path stays in the
	// path attribute.
	ArtifactExecutablePrefix = "executable/"
	// ArtifactExecutables summarizes what this probe read and what it did not.
	ArtifactExecutables = "system/executables"

	artifactTypeExecutable    = "executable"
	artifactTypeExecutableSet = "executable-set"
)

// Bounds of one capture (T-03b B3). They are exported because the manual and
// the evidence record name the numbers, and a number that only exists inside a
// function cannot be cited.
const (
	// ExecutableMaxFileBytes is the largest file this probe hashes. A larger
	// one is recorded without a hash and with a diagnostic that names its size
	// and this bound.
	//
	// It is deliberately NOT probe.Limits.MaxFileBytes. That limit bounds what
	// a probe READS INTO MEMORY through the restricted file reader, and it is
	// 1 MiB; hashing keeps no bytes at all, only the 32 byte digest state, so
	// the memory argument does not apply. What this bound buys is TIME: a
	// capture cannot be turned into an hour of disk reads by a file somebody
	// left under /opt.
	ExecutableMaxFileBytes int64 = 128 << 20
	// ExecutableMaxFiles is the largest number of program files one capture
	// inspects. The programs are sorted by path and the ones beyond this
	// number are named in diagnostics, not silently dropped.
	ExecutableMaxFiles = 256
	// ExecutableMaxCandidates is the largest number of distinct CANDIDATE
	// paths one capture takes from its sources, and it bites before anything
	// is resolved.
	//
	// It is a separate bound from ExecutableMaxFiles because the two count
	// different work. Every candidate costs a path resolution (an
	// EvalSymlinks, and for a listening process a readlink of
	// /proc/<pid>/exe) whether or not the file survives to be hashed, so a
	// cap that applies AFTER resolution bounds the hashing and leaves the
	// resolution bounded only by how many units and sockets a host happens to
	// have: 512 units that may each name several ExecStart paths, plus up to
	// one candidate per listening process.
	//
	// 1024 is four times ExecutableMaxFiles, and that factor is the reason
	// for the number rather than the number itself. The cap must lie above
	// the unit selection cap (systemdMaxShowUnits, 512), or a host whose
	// every selected unit names one program would lose programs to this bound
	// instead of to the file cap; and it must leave room for the two shapes
	// that legitimately produce more candidates than files, several logical
	// paths that resolve to one program and paths that are refused before
	// they become files. Above it the extra resolutions buy nothing, because
	// only ExecutableMaxFiles programs are kept anyway. A capture that hits
	// this cap names the paths it dropped.
	ExecutableMaxCandidates = 1024

	// executablesHashChunkBytes is how much of a file one read step hashes.
	// The loop checks the context between steps, so a probe that runs into its
	// deadline stops inside a large file instead of after it.
	executablesHashChunkBytes = 8 << 20
	// executablesBatch is how many paths one "stat" or "dpkg -S" call names.
	executablesBatch = 64
	// executablesMaxDiagnostics caps the per-file diagnostics of one cause;
	// the rest is summarized in one further diagnostic.
	executablesMaxDiagnostics = 20
	// executablesMaxValueBytes caps one recorded attribute value that comes
	// from the host (playbook L6).
	executablesMaxValueBytes = 400
)

// ExecutableRoots returns the absolute file roots this probe may open, sorted.
//
// /usr/local is inside /usr and is therefore redundant as a root; it is listed
// because the requirement names it, and because a reader of the bundle should
// see the scope the way the requirement states it. The set artifact records
// this list, so a capture says what it was allowed to look at.
func ExecutableRoots() []string {
	return []string{"/bin", "/opt", "/sbin", "/snap", "/usr", "/usr/local"}
}

// ExecutableHomePrefixes returns the path prefixes this probe never reads,
// sorted. None of them lies inside ExecutableRoots, so the rule can only bite
// through a symlink that leads out of the roots, which is exactly the case it
// is there for: a program under /usr/local/bin that is a link into somebody's
// home directory is refused and reported, and its bytes are never read.
func ExecutableHomePrefixes() []string {
	return []string{"/home", "/root"}
}

// Attribute names of the program artifacts.
const (
	execAttrPath          = "path"
	execAttrRequestedPath = "requested_path"
	execAttrSize          = "size"
	execAttrMode          = "mode"
	execAttrOwner         = "owner"
	execAttrGroup         = "group"
	execAttrSHA256        = "sha256"
	execAttrHashState     = "hash_state"
	execAttrPackageOwner  = "package_owner"
	execAttrPackageSource = "package_owner_source"
	execAttrDivertedBy    = "diverted_by"
	execAttrOrigins       = "discovered_by"
	execAttrUnits         = "units"
	execAttrUnitCount     = "unit_count"
)

// Attribute names of the set artifact.
const (
	execAttrProgramCount     = "program_count"
	execAttrHashedCount      = "hashed_count"
	execAttrCandidateCount   = "candidate_path_count"
	execAttrCandidateDropped = "candidate_paths_dropped"
	execAttrRefusedCount     = "refused_count"
	execAttrUnreadableCount  = "unreadable_count"
	execAttrTooLargeCount    = "over_size_limit_count"
	execAttrOwnerNoneCount   = "package_owner_none_count"
	execAttrOwnerUnknownCnt  = "package_owner_unknown_count"
	execAttrFromSystemdCount = "from_systemd_count"
	execAttrFromSocketCount  = "from_listener_count"
	execAttrListTruncated    = "program_list_truncated"
	execAttrRoots            = "roots"
	execAttrMaxFileBytes     = "max_file_bytes"
	execAttrMaxFiles         = "max_files"
	execAttrMaxCandidates    = "max_candidate_paths"
	execAttrHashAlgorithm    = "hash_algorithm"
	// execAttrPackageVerified states, in the bundle rather than only in the
	// manual, that no program was verified against its package. It is the
	// machine readable half of the difference between an observation and a
	// claim: package_owner is what the package database says about the PATH,
	// and only sha256 says anything about the BYTES.
	execAttrPackageVerified = "package_contents_verified"
	execAttrStatVersion     = "stat_version"
	execAttrDpkgVersion     = "dpkg_version"
)

// Values of the hash_state attribute. The state is recorded for every program
// artifact, so a missing sha256 is a stated fact with a cause and never an
// artifact that happens to look unchanged.
const (
	// HashStateCaptured: the digest is the SHA-256 of the whole file.
	HashStateCaptured = "captured"
	// HashStateOverSizeLimit: the file is larger than ExecutableMaxFileBytes.
	HashStateOverSizeLimit = "over_size_limit"
	// HashStatePermissionDenied: the account may not read the file.
	HashStatePermissionDenied = "permission_denied"
	// HashStateUnreadable: the read failed for another reason, including a
	// file that changed while it was read.
	HashStateUnreadable = "unreadable"
	// HashStateNotRead: the capture ran out of time (or was cancelled) before
	// this file was read. It is a statement about the CAPTURE and not about
	// the file: nothing was learned about these bytes either way, which is
	// why it is not "unreadable".
	HashStateNotRead = "not_read"
)

// Values of the package_owner and package_owner_source attributes.
const (
	// PackageOwnerNone: the package database was asked and owns this path
	// (T-03b B4). It is a finding, not an error.
	PackageOwnerNone = "none"
	// PackageOwnerUnknown: ownership could not be determined at all, which is
	// not the same statement as "no package owns it".
	PackageOwnerUnknown = "unknown"

	// PackageSourceDpkg: "dpkg -S" named the package.
	PackageSourceDpkg = "dpkg"
	// PackageSourceDpkgNoMatch: "dpkg -S" was asked and named no package for
	// this path.
	PackageSourceDpkgNoMatch = "dpkg_no_match"
	// PackageSourceSnapPath: the path lies inside a mounted snap, whose name
	// is the second segment of the path. Measured on an Ubuntu 22.04 bastion:
	// "dpkg -S /snap/core22/1122/usr/bin/env" answers that no path matches,
	// because the files of a snap are not in the dpkg database at all.
	PackageSourceSnapPath = "snap_path"
	// PackageSourceDpkgUnavailable: dpkg could not be asked.
	PackageSourceDpkgUnavailable = "dpkg_unavailable"
)

// Values of the discovered_by attribute.
const (
	// OriginSystemdExecStart: a unit of the systemd system manager starts
	// this program.
	OriginSystemdExecStart = "systemd_exec_start"
	// OriginListenerProcess: a process that holds a listening socket runs
	// this program.
	OriginListenerProcess = "listener_process"
)

// Diagnostic codes this probe adds to the shared ones.
const (
	// DiagExecutableRefused: a path was not read because a rule of this probe
	// forbids it (outside the roots, under a home directory, a symlink that
	// leaves the roots, not a regular file).
	DiagExecutableRefused = "executable_refused"
	// DiagExecutableUnreadable: the file could not be read or its metadata
	// could not be taken.
	DiagExecutableUnreadable = "executable_unreadable"
	// DiagExecutableOverSizeLimit: the file is larger than
	// ExecutableMaxFileBytes and was not hashed.
	DiagExecutableOverSizeLimit = "executable_over_size_limit"
	// DiagExecutableCountCapped: more program files than ExecutableMaxFiles.
	DiagExecutableCountCapped = "executable_count_capped"
	// DiagExecutableCandidateCapped: more candidate paths than
	// ExecutableMaxCandidates, so the paths beyond the cap were never
	// resolved and never became artifacts.
	DiagExecutableCandidateCapped = "executable_candidate_capped"
	// DiagExecutableUnowned: no package owns this program (T-03b B4).
	DiagExecutableUnowned = "package_owner_none"
	// DiagExecutableOwnerUnknown: ownership could not be determined.
	DiagExecutableOwnerUnknown = "package_owner_unknown"
	// DiagExecutableSourceMissing: one of the two sources of candidate paths
	// could not be read, so this bundle knows the programs of the other one
	// only.
	DiagExecutableSourceMissing = "executable_source_missing"
	// DiagExecutableProcessUnreadable: /proc/<pid>/exe could not be read for
	// a process that holds a listening socket.
	DiagExecutableProcessUnreadable = "process_executable_unreadable"
	// DiagExecutableChangedWhileRead: the size stat reported and the number of
	// bytes the hash read differ, so the file was written between the two
	// reads.
	DiagExecutableChangedWhileRead = "executable_changed_while_read"
)

// Errors of the file seam. They are sentinels so a caller classifies a refusal
// without reading a message, and every one of them is a statement about the
// path, never about the file content.
var (
	// ErrExecutableOutsideRoots: the path is not inside ExecutableRoots.
	ErrExecutableOutsideRoots = errors.New("linux.executables: path is outside the allowed roots")
	// ErrExecutableHomePath: the path is inside a home directory.
	ErrExecutableHomePath = errors.New("linux.executables: path is under a home directory")
	// ErrExecutableSymlinkEscape: the path is inside the roots and resolves
	// outside them.
	ErrExecutableSymlinkEscape = errors.New("linux.executables: the path resolves outside the allowed roots")
	// ErrExecutableNotRegular: the resolved path is not a regular file.
	ErrExecutableNotRegular = errors.New("linux.executables: not a regular file")
	// ErrExecutableTooLarge: the file is larger than the hash limit.
	ErrExecutableTooLarge = errors.New("linux.executables: file is larger than the hash limit")
	// ErrExecutableChanged: the file changed between the stat and the last
	// byte of the hash, so the digest describes no single state of it.
	ErrExecutableChanged = errors.New("linux.executables: the file changed while it was read")
	// ErrExecutableDeletedTarget: the running program's file is gone. The
	// kernel appends " (deleted)" to /proc/<pid>/exe when the file behind a
	// running process has been replaced or removed (documented Linux
	// behaviour, not a measurement of this run).
	ErrExecutableDeletedTarget = errors.New("linux.executables: the running program's file has been replaced or removed")
	// ErrExecutableBadPID: the pid is not a decimal number.
	ErrExecutableBadPID = errors.New("linux.executables: pid is not a number")
)

// ProgramReader is the file seam of this probe: everything it needs from the
// file system, and nothing more. It is an interface so that the probe can be
// run against a directory a test created, with the real resolution, the real
// symlink check and the real streaming hash (see NewRootedProgramReader).
//
// It deliberately does not use probe.FileReader. That reader returns the whole
// file and refuses anything over probe.Limits.MaxFileBytes, which is the right
// seam for a configuration file and the wrong one for a 30 MiB program: the
// hash must stream and must keep nothing.
type ProgramReader interface {
	// Resolve returns the resolved absolute path of p: every symlink followed,
	// the result inside the allowed roots, outside every home prefix, and a
	// regular file. Every refusal is one of the sentinel errors above; an
	// operating system error (a missing file, a denied directory) is returned
	// as it came, so the caller can test it with errors.Is.
	Resolve(p string) (string, error)
	// ProcessExecutable returns the resolved path of the program a process
	// runs, from /proc/<pid>/exe. The link itself is read, never followed
	// blindly: the target goes through the same checks Resolve applies.
	ProcessExecutable(pid string) (string, error)
	// Hash streams the file at the resolved path p and returns its SHA-256 in
	// lowercase hex and the number of bytes it read. It keeps no file content:
	// a file larger than maxBytes is refused with ErrExecutableTooLarge before
	// anything is hashed, and a file that grows past maxBytes while it is read
	// is refused as well. The context bounds the read.
	Hash(ctx context.Context, p string, maxBytes int64) (sum string, size int64, err error)
}

// RootedProgramReader is the production ProgramReader: it opens files under
// its roots and nothing else.
//
// FSPrefix is the one concession to testability, and it is honest about what it
// is: the roots stay the LOGICAL absolute paths of a Linux host (/usr, /bin),
// and the prefix is prepended when a path is actually opened. In production it
// is empty. In a test it is a temporary directory, so the test exercises this
// very code (the root check, the symlink resolution, the size cap, the
// permission error) without needing a file outside the test directory and
// without ever touching the real system (playbook section 1 rule 5).
type RootedProgramReader struct {
	roots []string
	homes []string
	// prefix is the on-disk prefix as given, resolvedPrefix the same path with
	// its own symlinks resolved. Both are needed: a temporary directory on
	// macOS is handed out as /var/... and resolves to /private/var/..., so a
	// resolved file path can only be mapped back to a logical path through the
	// resolved form.
	prefix         string
	resolvedPrefix string
}

// NewRootedProgramReader returns a reader for the logical roots and home
// prefixes, opening under fsPrefix (empty in production). Roots and prefixes
// that are not absolute logical paths are ignored, so a caller cannot widen the
// scope by accident.
func NewRootedProgramReader(roots, homes []string, fsPrefix string) *RootedProgramReader {
	r := &RootedProgramReader{prefix: fsPrefix, resolvedPrefix: fsPrefix}
	if fsPrefix != "" {
		if resolved, err := filepath.EvalSymlinks(fsPrefix); err == nil {
			r.resolvedPrefix = resolved
		}
	}
	r.roots = cleanLogicalPaths(roots)
	r.homes = cleanLogicalPaths(homes)
	return r
}

// DefaultProgramReader returns the production reader: the roots and home
// prefixes of this probe, opening the real file system.
func DefaultProgramReader() *RootedProgramReader {
	return NewRootedProgramReader(ExecutableRoots(), ExecutableHomePrefixes(), "")
}

// Roots returns the logical roots of the reader, sorted.
func (r *RootedProgramReader) Roots() []string { return append([]string(nil), r.roots...) }

// cleanLogicalPaths keeps the absolute slash paths of in, cleaned, sorted and
// without duplicates.
func cleanLogicalPaths(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if !path.IsAbs(p) || strings.ContainsRune(p, 0) {
			continue
		}
		c := path.Clean(p)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// check applies the two path rules to a logical path and returns it cleaned.
func (r *RootedProgramReader) check(p string) (string, error) {
	if !path.IsAbs(p) || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: %q is not an absolute path", ErrExecutableOutsideRoots, p)
	}
	c := path.Clean(p)
	for _, home := range r.homes {
		if underLogical(c, home) {
			return "", fmt.Errorf("%w: %q is under %q", ErrExecutableHomePath, c, home)
		}
	}
	for _, root := range r.roots {
		if underLogical(c, root) {
			return c, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrExecutableOutsideRoots, c)
}

// underLogical reports whether p is root or lies below it.
func underLogical(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// disk maps a logical path to the path on this file system.
func (r *RootedProgramReader) disk(logical string) string {
	rel := filepath.FromSlash(strings.TrimPrefix(logical, "/"))
	if r.prefix == "" {
		return string(filepath.Separator) + rel
	}
	return filepath.Join(r.prefix, rel)
}

// logical maps an on-disk path back to a logical path. A path that is not under
// the prefix left the test directory, which is the same failure a symlink out of
// the roots is in production.
//
// Both prefix forms are tried, because the two on-disk paths that reach this
// function come from different places: a path from filepath.EvalSymlinks has
// every symlink of the prefix itself resolved, and the target of a
// /proc/<pid>/exe link has not.
func (r *RootedProgramReader) logical(disk string) (string, error) {
	if r.prefix == "" {
		return filepath.ToSlash(disk), nil
	}
	for _, prefix := range []string{r.resolvedPrefix, r.prefix} {
		if prefix == "" {
			continue
		}
		rel, err := filepath.Rel(prefix, disk)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return "/" + filepath.ToSlash(rel), nil
	}
	return "", fmt.Errorf("%w: %q", ErrExecutableSymlinkEscape, disk)
}

// Resolve implements ProgramReader.
func (r *RootedProgramReader) Resolve(p string) (string, error) {
	clean, err := r.check(p)
	if err != nil {
		return "", err
	}
	return r.resolveChecked(clean)
}

// resolveChecked resolves a logical path that already passed check.
func (r *RootedProgramReader) resolveChecked(clean string) (string, error) {
	resolvedDisk, err := filepath.EvalSymlinks(r.disk(clean))
	if err != nil {
		return "", err
	}
	resolved, err := r.logical(resolvedDisk)
	if err != nil {
		return "", err
	}
	if resolved != clean {
		// The path is a link. Where it leads decides, and a target outside the
		// roots is an escape and not merely an unknown path: the difference is
		// worth its own error, because it is the finding.
		if _, err := r.check(resolved); err != nil {
			if errors.Is(err, ErrExecutableHomePath) {
				return "", fmt.Errorf("%w: %q resolves to %q", ErrExecutableHomePath, clean, resolved)
			}
			return "", fmt.Errorf("%w: %q resolves to %q", ErrExecutableSymlinkEscape, clean, resolved)
		}
	}
	fi, err := os.Lstat(resolvedDisk)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is a %s", ErrExecutableNotRegular, resolved, fi.Mode().Type())
	}
	return resolved, nil
}

// ProcessExecutable implements ProgramReader.
func (r *RootedProgramReader) ProcessExecutable(pid string) (string, error) {
	if pid == "" || strings.TrimLeft(pid, "0123456789") != "" {
		return "", fmt.Errorf("%w: %q", ErrExecutableBadPID, pid)
	}
	link := "/proc/" + pid + "/exe"
	target, err := os.Readlink(r.disk(link))
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(target, " (deleted)") {
		return "", fmt.Errorf("%w: %s", ErrExecutableDeletedTarget, strings.TrimSuffix(target, " (deleted)"))
	}
	if !path.IsAbs(filepath.ToSlash(target)) {
		return "", fmt.Errorf("%w: %q is not an absolute path", ErrExecutableOutsideRoots, target)
	}
	// In a test the link points inside the test directory; map it back to the
	// logical path before the rules are applied, so the same rules decide in
	// both worlds.
	logical, err := r.logical(target)
	if err != nil {
		return "", err
	}
	clean, err := r.check(logical)
	if err != nil {
		return "", err
	}
	return r.resolveChecked(clean)
}

// Hash implements ProgramReader.
func (r *RootedProgramReader) Hash(ctx context.Context, p string, maxBytes int64) (string, int64, error) {
	if maxBytes <= 0 {
		maxBytes = ExecutableMaxFileBytes
	}
	clean, err := r.check(p)
	if err != nil {
		return "", 0, err
	}
	disk := r.disk(clean)
	before, err := os.Lstat(disk)
	if err != nil {
		return "", 0, err
	}
	if !before.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %s is a %s", ErrExecutableNotRegular, clean, before.Mode().Type())
	}
	if before.Size() > maxBytes {
		return "", before.Size(), fmt.Errorf("%w: %s has %d bytes, the limit is %d", ErrExecutableTooLarge, clean, before.Size(), maxBytes)
	}
	// #nosec G304 -- the path is not user input: it comes from an ExecStart
	// property or from /proc/<pid>/exe, it passed the root and home rules of
	// check, and it was resolved before it got here. The open below is
	// immediately verified to be the same regular file Lstat saw (os.SameFile),
	// which closes the window for a symlink swapped in after the resolution.
	f, err := os.Open(disk)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, before) {
		return "", 0, fmt.Errorf("%w: %s", ErrExecutableChanged, clean)
	}
	h := sha256.New()
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return "", n, err
		}
		m, err := io.CopyN(h, f, executablesHashChunkBytes)
		n += m
		if n > maxBytes {
			return "", n, fmt.Errorf("%w: %s passed %d bytes while it was read", ErrExecutableTooLarge, clean, maxBytes)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", n, err
		}
	}
	if n != fi.Size() {
		// The file was written while it was read, so the digest belongs to no
		// single state of it. Reporting it as a hash would be a false record.
		return "", n, fmt.Errorf("%w: %s had %d bytes and %d were read", ErrExecutableChanged, clean, fi.Size(), n)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ExecutableArtifactID returns the artifact id of a program file:
// "executable/" plus the resolved path without its leading slash, sanitized
// with the same rule the mount artifacts use (mountArtifactSuffix), so one
// sanitizer decides for every path derived id of this package. The unsanitized
// path stays in the path attribute.
func ExecutableArtifactID(resolvedPath string) string {
	return ArtifactExecutablePrefix + mountArtifactSuffix(resolvedPath)
}

// SnapNameFromPath returns the name of the snap a path belongs to, or the empty
// string when the path is not inside a mounted snap.
//
// The layout is "/snap/<name>/<revision>/...": measured on an Ubuntu 22.04
// bastion, /snap/core22 holds the revision directories 1122 and 2955 and the
// symlink "current" pointing at one of them, and the executable
// /snap/core22/1122/usr/bin/env belongs to the snap "core22". The revision is
// part of the resolved path and therefore already recorded; it needs no
// attribute of its own.
//
// "/snap/bin/<command>" is NOT a snap file: measured on both hosts, every entry
// of /snap/bin is a symlink to /usr/bin/snap, the launcher from the snapd
// package. Those paths resolve to /usr/bin/snap before they get here, so the
// two segment form never reaches this function as a snap.
func SnapNameFromPath(resolvedPath string) string {
	rest, ok := strings.CutPrefix(path.Clean(resolvedPath), "/snap/")
	if !ok {
		return ""
	}
	segs := strings.Split(rest, "/")
	if len(segs) < 3 || segs[0] == "" || segs[1] == "" || segs[2] == "" {
		return ""
	}
	return segs[0]
}

// ProgramFile is what the probe learned about one program file. Every field is
// a fact with a source: Requested are the paths the discovery named, Resolved
// is what the file system says they are, the metadata comes from "stat", the
// digest from reading the file, and the ownership from "dpkg -S" or from the
// path of a snap.
type ProgramFile struct {
	// Resolved is the absolute path with every symlink followed.
	Resolved string
	// Requested holds the paths the sources named, sorted and deduplicated. It
	// is empty when no source named anything but the resolved path itself.
	Requested []string
	// Origins are the OriginSystemd... constants, sorted.
	Origins []string
	// Units are the systemd units whose ExecStart names this program, sorted.
	Units []string
	// Mode ("0755"), Owner, Group and StatSize come from "stat"; they are
	// empty when stat could not be asked or did not answer for this path.
	Mode     string
	Owner    string
	Group    string
	StatSize string
	// SHA256 is the lowercase hex digest, empty unless HashState is
	// HashStateCaptured. HashedBytes is the number of bytes that produced it.
	SHA256      string
	HashState   string
	HashedBytes int64
	// PackageOwner and PackageSource answer the ownership question and say how
	// it was answered. DivertedBy names the package that diverts this path,
	// where "dpkg -S" reported a diversion.
	PackageOwner  string
	PackageSource string
	DivertedBy    string
}

// ExecutablesProbe collects the programs behind the services and the listening
// sockets of a Linux host.
type ExecutablesProbe struct {
	reader ProgramReader
}

// NewExecutablesProbe returns the probe with the production file seam.
func NewExecutablesProbe() *ExecutablesProbe {
	return &ExecutablesProbe{reader: DefaultProgramReader()}
}

// NewExecutablesProbeWithReader returns the probe with an injected file seam.
func NewExecutablesProbeWithReader(r ProgramReader) *ExecutablesProbe {
	return &ExecutablesProbe{reader: r}
}

// Descriptor implements probe.Probe.
func (p *ExecutablesProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                ExecutablesProbeID,
		Version:           ExecutablesProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		// Hashing up to ExecutableMaxFiles programs is the one probe of this
		// package whose work is bounded by disk speed rather than by a tool,
		// so it asks for more time than its siblings. The timeout is also the
		// deadline of each command it runs (capture.probeTimeout).
		DefaultTimeout: 180 * time.Second,
		Sensitivity:    trustfreeze.SensitivityInternal,
		Provides:       []string{ArtifactExecutablePrefix, ArtifactExecutables},
	}
}

// RequiredTools implements the optional tool interface of the capture package:
// doctor resolves these names and never runs them.
//
// All four are named although none of them alone is decisive: systemctl and ss
// each supply candidate paths and the probe survives the loss of either one,
// stat supplies the metadata and dpkg the ownership. A capture that has none of
// them records no program, so doctor should say which one is missing before
// somebody reads an empty result as an empty host.
func (p *ExecutablesProbe) RequiredTools() []string {
	return []string{ExecutablesToolDpkg, ListenersTool, ExecutablesToolStat, systemctlExe}
}

// EvidenceClaims implements probe.EvidenceClaimer. The parsers and the file
// seam are covered by fixture tests that run on any host, and the package
// compiles for Linux. Whether the probe ran on a real Linux host is not decided
// in code (SPEC-0471 TF06-R7).
func (p *ExecutablesProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe: availability only, nothing is collected.
//
// The two sources of candidate paths are systemctl and ss. With neither of them
// there is no program to look for, and that is unavailable with both names in
// the reason. With one of them the probe runs and reports the other as a named
// gap, because half the programs of a host are still worth hashing.
func (p *ExecutablesProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("linux.executables has no source on " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	var denied bool
	for _, exe := range []string{systemctlExe, ListenersTool} {
		_, err := host.Runner.LookPath(exe)
		switch {
		case err == nil:
			return probe.Supported()
		case errors.Is(err, probe.ErrPermissionDenied):
			denied = true
		}
	}
	if denied {
		return probe.PermissionDenied("neither " + systemctlExe + " nor " + ListenersTool + " is executable by this account")
	}
	return probe.Unavailable("neither " + systemctlExe + " nor " + ListenersTool + " was found: without them no program of this host can be named")
}

// Collect implements probe.Probe.
func (p *ExecutablesProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := &executablesCollector{
		ctx:        ctx,
		cc:         cc,
		s:          newNetProbeState(ctx, cc),
		reader:     p.readerOrDefault(),
		candidates: map[string]*programCandidate{},
	}
	res := c.s.base(ExecutablesProbeID, ExecutablesProbeVersion, start)
	c.discoverFromSystemd()
	c.discoverFromListeners()
	files := c.inspect()
	c.resolveOwnership(files)
	arts := c.artifacts(files, start)
	switch {
	case c.timedOut:
		// A capture that ran out of time is a timeout, not a partial result
		// with a list of unreadable files (SPEC-0471 TF06-R2, playbook L1).
		res.Reason = strings.Join(c.reasons, "; ")
		res.Status = trustfreeze.StatusTimeout
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTimeout, Message: res.Reason}
	case len(c.reasons) > 0:
		res.Status, res.Reason = trustfreeze.StatusPartial, strings.Join(c.reasons, "; ")
	default:
		res.Status = trustfreeze.StatusCaptured
	}
	return c.s.finish(res, arts, start)
}

func (p *ExecutablesProbe) readerOrDefault() ProgramReader {
	if p.reader == nil {
		return DefaultProgramReader()
	}
	return p.reader
}

// programCandidate is one path a source named, before anything was read.
type programCandidate struct {
	path    string
	origins map[string]bool
	units   map[string]bool
}

// executablesCollector gathers one Collect call.
type executablesCollector struct {
	ctx    context.Context
	cc     probe.CollectContext
	s      *netProbeState
	reader ProgramReader

	candidates map[string]*programCandidate
	reasons    []string

	// dropped counts the candidate paths ExecutableMaxCandidates refused and
	// droppedNames keeps the first executablesMaxDiagnostics of them, so the
	// bookkeeping of a capture that hits the cap is itself bounded.
	dropped      int
	droppedNames []string
	// timedOut is set when the context ended while the programs were being
	// read. It outranks every partial reason, because a capture that ran out
	// of time made no statement about the files it did not reach.
	timedOut bool

	statVersion string
	dpkgVersion string

	// counters of the set artifact.
	refused    int
	unreadable int
	tooLarge   int
	fromUnit   int
	fromSocket int
	truncated  bool
}

func (c *executablesCollector) warn(code, field, msg string) { c.s.warn(code, field, msg) }

// degrade records why the run is partial.
func (c *executablesCollector) degrade(reason string) { c.reasons = append(c.reasons, reason) }

// addCandidate records one path a source named.
//
// A path that is already known costs nothing and merges its origin, so the
// counts stay true. A NEW path beyond ExecutableMaxCandidates is dropped here,
// before it is resolved: the cap bounds the work of this probe, and a cap that
// bounds work has to bite before the work happens.
func (c *executablesCollector) addCandidate(p, origin, unit string) {
	p = strings.TrimSpace(p)
	if p == "" {
		return
	}
	cand := c.candidates[p]
	if cand == nil {
		if c.candidatesFull() {
			c.dropCandidate(p)
			return
		}
		cand = &programCandidate{path: p, origins: map[string]bool{}, units: map[string]bool{}}
		c.candidates[p] = cand
	}
	cand.origins[origin] = true
	if unit != "" {
		cand.units[unit] = true
	}
}

// candidatesFull reports whether the candidate cap is reached.
func (c *executablesCollector) candidatesFull() bool {
	return len(c.candidates) >= ExecutableMaxCandidates
}

// dropCandidate records one candidate the cap refused. what is a path, or the
// name of a listening process where the path was never read (a pid is volatile
// and is never recorded, playbook L8).
func (c *executablesCollector) dropCandidate(what string) {
	c.dropped++
	if len(c.droppedNames) < executablesMaxDiagnostics {
		c.droppedNames = append(c.droppedNames, executablesCapValue(what))
	}
}

// reportCandidateCap names what the candidate cap left out. It is called once,
// after both sources have run and before anything is resolved, so the
// diagnostics of a capped capture are one block and not one per source.
func (c *executablesCollector) reportCandidateCap() {
	if c.dropped == 0 {
		return
	}
	for _, name := range c.droppedNames {
		c.warn(DiagExecutableCandidateCapped, execAttrPath, fmt.Sprintf(
			"%s was not inspected: the sources of this capture named more than the %d candidate path(s) the limit allows, and the paths beyond it are not resolved",
			name, ExecutableMaxCandidates))
	}
	if rest := c.dropped - len(c.droppedNames); rest > 0 {
		c.warn(DiagExecutableCandidateCapped, execAttrPath,
			fmt.Sprintf("%d further candidate path(s) were not inspected for the same reason", rest))
	}
	c.degrade(fmt.Sprintf("%d candidate path(s) beyond the limit of %d were not inspected", c.dropped, ExecutableMaxCandidates))
}

// runBatched runs a call whose argument vector names many paths and records a
// SHORT source for it.
//
// netProbeState.run records the whole argument vector as the source, which is
// right for a two flag call and wrong for one that names up to
// executablesBatch paths: that source would be kilobytes long and would be
// repeated in the provenance of every artifact of this probe. The tool
// invocation the engine persists still carries the full argument vector, so
// nothing about the call is lost; only the provenance says "command:stat"
// instead of repeating 64 paths, which is what the sibling probes do
// (sudo.go does the same for its own stat call).
func (c *executablesCollector) runBatched(exe string, args []string, source string) netCmd {
	before := len(c.s.sources)
	cmd := c.s.run(exe, args)
	if len(c.s.sources) > before {
		c.s.sources = c.s.sources[:before]
	}
	if cmd.Status == trustfreeze.StatusCaptured {
		c.s.addSource(source)
	}
	return cmd
}

// lookTool reports whether an executable resolves, without running it.
func (c *executablesCollector) lookTool(exe string) bool {
	if c.cc.Runner == nil {
		return false
	}
	_, err := c.cc.Runner.LookPath(exe)
	return err == nil
}

// discoverFromSystemd collects the ExecStart paths of the units the systemd
// selection rule picks. It asks for two properties only: the runtime state of
// those units is the subject of linux.systemd, and asking again for all of it
// would double the output for nothing.
func (c *executablesCollector) discoverFromSystemd() {
	if !c.lookTool(systemctlExe) {
		c.warn(DiagExecutableSourceMissing, "systemd_exec_start",
			systemctlExe+" was not found, so the programs the units of this host start are not in this bundle")
		c.degrade("the programs behind the systemd units are not in this bundle: " + systemctlExe + " was not found")
		return
	}
	cmd := c.s.run(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"})
	if cmd.Status != trustfreeze.StatusCaptured {
		c.warn(netDiagCode(cmd.Status), "systemd_exec_start", "systemctl list-unit-files: "+cmd.Detail)
		c.degrade("the unit file list could not be read: " + cmd.Detail)
		return
	}
	if cmd.Res.StdoutTruncated {
		c.noteTruncation(cmd, "systemd_exec_start", "the units beyond the cut were not asked about")
	}
	files, issues := ParseUnitFiles(cmd.Res.Stdout.Bytes())
	if len(issues) > 0 {
		c.warn(DiagSystemdUnreadRecord, "systemd_exec_start",
			fmt.Sprintf("systemctl list-unit-files: %d record(s) could not be read", len(issues)))
		c.degrade(fmt.Sprintf("%d record(s) of the unit file list were not read", len(issues)))
	}
	selected, cut := SelectUnitsForShow(files, systemdMaxShowUnits)
	if cut {
		c.warn(DiagSystemdSelectionTruncated, "systemd_exec_start",
			fmt.Sprintf("more than %d units matched the selection rule; the programs of the rest are not in this bundle", systemdMaxShowUnits))
		c.degrade("the unit selection was cut")
	}
	if len(selected) == 0 {
		return
	}
	// A "systemctl show" call that names several units can stop before it has
	// answered for all of them, so the names that went unanswered are asked
	// for again one at a time (measured on an Ubuntu 22.04 bastion, see
	// systemd.go and testdata/systemd/systemctl-show-batch-aborted.txt).
	answered := map[string]bool{}
	for i := 0; i < len(selected); i += systemdShowBatch {
		end := i + systemdShowBatch
		if end > len(selected) {
			end = len(selected)
		}
		batch := selected[i:end]
		if !c.showExecStart(batch, answered) {
			c.degrade(fmt.Sprintf("the programs of %d unit(s) could not be read", len(batch)))
			continue
		}
		var missing []string
		for _, u := range batch {
			if !answered[u] {
				missing = append(missing, u)
			}
		}
		if len(missing) == 0 || len(batch) == 1 {
			continue
		}
		c.warn(DiagSystemdBatchSplit, "systemd_exec_start", fmt.Sprintf(
			"systemctl show answered for %d of %d unit(s) starting at %s and stopped there; the remaining %d were asked for one at a time",
			len(batch)-len(missing), len(batch), batch[0], len(missing)))
		for _, u := range missing {
			c.showExecStart([]string{u}, answered)
		}
	}
	var unanswered int
	for _, u := range selected {
		if !answered[u] {
			unanswered++
		}
	}
	if unanswered > 0 {
		// The manager returned no property block at all for these units, which
		// is a gap. A unit that answered without an ExecStart is a different
		// thing entirely: a timer, a socket or a mount starts no program of its
		// own, and that is a fact about the unit, not a hole in this capture.
		c.warn(trustfreeze.DiagFieldMissing, "systemd_exec_start",
			fmt.Sprintf("the manager returned no properties for %d of %d selected unit(s), so the program they start is unknown", unanswered, len(selected)))
		c.degrade(fmt.Sprintf("the program of %d selected unit(s) is unknown", unanswered))
	}
}

// showExecStart asks for Id and ExecStart of the named units and records every
// path it got. It reports whether the call ran and was parsed at all.
func (c *executablesCollector) showExecStart(units []string, answered map[string]bool) bool {
	args := append([]string{"show", "--no-pager", "-p", ShowPropID + "," + ShowPropExecStart}, units...)
	cmd := c.runBatched(systemctlExe, args, "command:systemctl show")
	if cmd.Status != trustfreeze.StatusCaptured && cmd.Status != trustfreeze.StatusFailed {
		// Tool missing, refused or killed at the deadline: asking again would
		// repeat it. A non-zero exit is not in this class, because a refused
		// unit name ends the call after it has answered for the units before
		// it, and those answers are worth keeping.
		c.warn(netDiagCode(cmd.Status), "systemd_exec_start", "systemctl show: "+cmd.Detail)
		return false
	}
	if cmd.Res.ExitCode != 0 {
		// A name the manager refuses ends the call after the units before it
		// were answered for, so a non-zero exit is a diagnostic and not the end
		// of the run (measured, see systemd.go).
		c.warn(DiagSystemdExitCode, "systemd_exec_start",
			fmt.Sprintf("systemctl show exited %d for %d unit(s) starting at %s", cmd.Res.ExitCode, len(units), units[0]))
	}
	if cmd.Res.StdoutTruncated {
		c.noteTruncation(cmd, "systemd_exec_start", "the programs of the units beyond the cut were not read")
	}
	blocks, issues := ParseShowBlocks(cmd.Res.Stdout.Bytes())
	if len(issues) > 0 {
		c.warn(DiagSystemdUnreadRecord, "systemd_exec_start",
			fmt.Sprintf("systemctl show: %d record(s) could not be read", len(issues)))
	}
	for _, b := range blocks {
		unit := b.First(ShowPropID)
		if unit == "" {
			continue
		}
		answered[unit] = true
		// Every ExecStart of the unit, not only the first: a unit with several
		// start commands runs several programs, and the unit artifact of
		// linux.systemd records the first path and the count of the rest.
		for _, raw := range b.Values[ShowPropExecStart] {
			if p := ParseExecStartPath(raw); p != "" {
				c.addCandidate(p, OriginSystemdExecStart, unit)
			}
		}
	}
	return len(blocks) > 0
}

// discoverFromListeners collects the programs behind the listening sockets
// whose owning process is observable.
func (c *executablesCollector) discoverFromListeners() {
	if !c.lookTool(ListenersTool) {
		c.warn(DiagExecutableSourceMissing, "listener_process",
			ListenersTool+" was not found, so the programs behind the listening sockets of this host are not in this bundle")
		c.degrade("the programs behind the listening sockets are not in this bundle: " + ListenersTool + " was not found")
		return
	}
	cmd := c.s.run(ListenersTool, []string{"-H", "-lntup"})
	if cmd.Status != trustfreeze.StatusCaptured {
		c.warn(netDiagCode(cmd.Status), "listener_process", "ss -H -lntup: "+cmd.Detail)
		c.degrade("the listening sockets could not be read: " + cmd.Detail)
		return
	}
	if cmd.Res.StdoutTruncated {
		c.noteTruncation(cmd, "listener_process", "the sockets beyond the cut were not read")
	}
	listeners, _ := ParseSSListeners(cmd.Res.Stdout.Bytes())
	// One pid can hold many sockets, so each pid is read once. The pid itself
	// is volatile and never recorded: it is the key of this map and nothing
	// else (playbook L8).
	seen := map[string]bool{}
	denied := map[string]bool{}
	refused := map[string]bool{}
	var noOwner int
	for _, l := range listeners {
		if !l.OwnerKnown() {
			noOwner++
			continue
		}
		for _, pr := range l.Processes {
			if seen[pr.PID] {
				continue
			}
			seen[pr.PID] = true
			if c.candidatesFull() {
				// The readlink is work of the same class as the resolution it
				// feeds, so the cap stops it here too instead of after it.
				c.dropCandidate(pr.Name)
				continue
			}
			resolved, err := c.reader.ProcessExecutable(pr.PID)
			switch {
			case err == nil:
				c.addCandidate(resolved, OriginListenerProcess, "")
			case executablesRefusal(err):
				// The link was read and a rule of this probe refused where it
				// leads. That is a finding of its own: something that listens
				// on this host runs a program outside the ground this probe
				// may read. The reason names the target, which is stable; the
				// pid is not and is never recorded (playbook L8).
				c.refused++
				refused[executablesCapValue(executablesErrorReason(err))] = true
			default:
				// The link could not be read at all, which unprivileged is the
				// normal answer for another account's process. The process
				// name is stable, so the name is what the diagnostic carries.
				denied[executablesCapValue(pr.Name)] = true
			}
		}
	}
	if noOwner > 0 {
		c.warn(probe.DiagFieldPermissionDenied, "listener_process", fmt.Sprintf(
			"ss named no owning process for %d of %d listening socket(s), so the program behind them is not in this bundle; unprivileged ss fills the owner column for the caller's own processes only",
			noOwner, len(listeners)))
		c.degrade(fmt.Sprintf("the program behind %d listening socket(s) is unknown", noOwner))
	}
	if len(refused) > 0 {
		reasons := netSortedKeys(refused)
		shown := reasons
		if len(shown) > executablesMaxDiagnostics {
			shown = shown[:executablesMaxDiagnostics]
		}
		for _, r := range shown {
			c.warn(DiagExecutableRefused, "listener_process",
				"the program of a process that holds a listening socket was not read: "+r)
		}
		if rest := len(reasons) - len(shown); rest > 0 {
			c.warn(DiagExecutableRefused, "listener_process",
				fmt.Sprintf("%d further listening process(es) run a program this probe may not read", rest))
		}
		c.degrade(fmt.Sprintf("%d listening process(es) run a program this probe may not read", len(reasons)))
	}
	if len(denied) > 0 {
		names := netSortedKeys(denied)
		shown, cut := privCapList(names, executablesMaxValueBytes)
		msg := fmt.Sprintf("the program of %d process(es) that hold a listening socket could not be read from /proc/<pid>/exe: %s", len(names), shown)
		if cut {
			msg += " (the list of names is cut)"
		}
		c.warn(DiagExecutableProcessUnreadable, "listener_process", msg)
		c.degrade(fmt.Sprintf("the program of %d listening process(es) could not be read", len(names)))
	}
}

// executablesRefusal reports whether err is a rule of this probe refusing a
// path, as opposed to the operating system refusing to answer at all.
func executablesRefusal(err error) bool {
	for _, sentinel := range []error{
		ErrExecutableOutsideRoots, ErrExecutableHomePath, ErrExecutableSymlinkEscape,
		ErrExecutableNotRegular, ErrExecutableDeletedTarget,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// noteTruncation reports what a byte cap cut from a command output.
func (c *executablesCollector) noteTruncation(cmd netCmd, field, consequence string) {
	outCap, _ := outputCap(c.cc)
	c.warn(trustfreeze.DiagOutputTruncated, field,
		truncationNote(cmd.Res.Executable, "stdout", len(cmd.Res.Stdout.Bytes()), cmd.Res.StdoutBytes, outCap, consequence))
	c.degrade(consequence)
	c.truncated = true
}

// inspect turns the candidate paths into program files: resolve, cap, take the
// metadata, hash. The returned list is sorted by resolved path.
func (c *executablesCollector) inspect() []*ProgramFile {
	c.reportCandidateCap()
	byResolved := map[string]*ProgramFile{}
	var refusedMsgs []string
	for _, p := range netSortedKeys(c.candidates) {
		cand := c.candidates[p]
		resolved, err := c.reader.Resolve(p)
		if err != nil {
			c.refused++
			refusedMsgs = append(refusedMsgs, executablesRefusalMessage(p, err))
			continue
		}
		f := byResolved[resolved]
		if f == nil {
			f = &ProgramFile{Resolved: resolved, HashState: HashStateUnreadable}
			byResolved[resolved] = f
		}
		if resolved != p {
			f.Requested = append(f.Requested, p)
		}
		for o := range cand.origins {
			if !slices.Contains(f.Origins, o) {
				f.Origins = append(f.Origins, o)
			}
		}
		for u := range cand.units {
			if !slices.Contains(f.Units, u) {
				f.Units = append(f.Units, u)
			}
		}
	}
	c.reportRefusals(refusedMsgs)

	files := make([]*ProgramFile, 0, len(byResolved))
	for _, k := range netSortedKeys(byResolved) {
		f := byResolved[k]
		sort.Strings(f.Requested)
		sort.Strings(f.Origins)
		sort.Strings(f.Units)
		files = append(files, f)
	}
	if len(files) > ExecutableMaxFiles {
		c.reportCountCap(files[ExecutableMaxFiles:])
		files = files[:ExecutableMaxFiles]
		c.truncated = true
	}
	// The origins are counted after the cap, so the counts of the set artifact
	// add up to the programs it reports and not to the ones it dropped.
	for _, f := range files {
		for _, o := range f.Origins {
			switch o {
			case OriginSystemdExecStart:
				c.fromUnit++
			case OriginListenerProcess:
				c.fromSocket++
			}
		}
	}
	c.collectMetadata(files)
	c.hash(files)
	return files
}

// reportRefusals turns the refused paths into diagnostics: each one names the
// file and the cause, and the run is partial.
func (c *executablesCollector) reportRefusals(msgs []string) {
	if len(msgs) == 0 {
		return
	}
	shown := msgs
	if len(shown) > executablesMaxDiagnostics {
		shown = shown[:executablesMaxDiagnostics]
	}
	for _, m := range shown {
		c.warn(DiagExecutableRefused, execAttrPath, m)
	}
	if rest := len(msgs) - len(shown); rest > 0 {
		c.warn(DiagExecutableRefused, execAttrPath, fmt.Sprintf("%d further path(s) were refused for the same kinds of reason", rest))
	}
	c.degrade(fmt.Sprintf("%d named path(s) were not read", len(msgs)))
}

// reportCountCap names the program files the per capture cap dropped.
func (c *executablesCollector) reportCountCap(dropped []*ProgramFile) {
	shown := dropped
	if len(shown) > executablesMaxDiagnostics {
		shown = shown[:executablesMaxDiagnostics]
	}
	for _, f := range shown {
		c.warn(DiagExecutableCountCapped, execAttrPath, fmt.Sprintf(
			"%s was not inspected: this capture already holds the %d program(s) the limit allows", f.Resolved, ExecutableMaxFiles))
	}
	if rest := len(dropped) - len(shown); rest > 0 {
		c.warn(DiagExecutableCountCapped, execAttrPath, fmt.Sprintf("%d further program(s) were not inspected for the same reason", rest))
	}
	c.degrade(fmt.Sprintf("%d program(s) beyond the limit of %d were not inspected", len(dropped), ExecutableMaxFiles))
}

// collectMetadata asks stat for mode, owner, group and size of every program.
// A missing stat is a named gap and not a failure: the digest does not depend
// on it.
func (c *executablesCollector) collectMetadata(files []*ProgramFile) {
	if len(files) == 0 {
		return
	}
	if !c.lookTool(ExecutablesToolStat) {
		c.warn(probe.DiagFieldUnavailable, execAttrMode,
			ExecutablesToolStat+" was not found, so mode, owner, group and size of the programs are not in this bundle")
		c.degrade("mode, owner and group of the programs are unknown: " + ExecutablesToolStat + " was not found")
		return
	}
	c.statVersion = c.s.toolVersion(ExecutablesToolStat, []string{"--version"}, "stat-version.txt")
	info := map[string]StatInfo{}
	for i := 0; i < len(files); i += executablesBatch {
		end := i + executablesBatch
		if end > len(files) {
			end = len(files)
		}
		// The paths are already resolved, so "-L" changes nothing about the
		// answer; it is there because it makes the answer about the FILE even
		// if the path was replaced by a symlink after the resolution.
		args := []string{"-L", "-c", "%n %a %U %G %s"}
		for _, f := range files[i:end] {
			args = append(args, f.Resolved)
		}
		cmd := c.runBatched(ExecutablesToolStat, args, "command:stat")
		if cmd.Status != trustfreeze.StatusCaptured && cmd.Status != trustfreeze.StatusFailed {
			c.warn(netDiagCode(cmd.Status), execAttrMode, "stat: "+cmd.Detail)
			continue
		}
		// A missing path makes stat exit non-zero while the other lines are
		// still printed, so the output is parsed whatever the exit code says
		// (measured on both hosts).
		c.s.evidenceIfAny(fmt.Sprintf("stat-%02d.txt", i/executablesBatch+1), "stdout:stat", cmd.Res.Stdout, cmd.Res.StdoutTruncated)
		parsed, diags := ParseStat(cmd.Res.Stdout.Bytes())
		for _, d := range diags {
			c.warn(d.Code, execAttrMode, d.Message)
		}
		for k, v := range parsed {
			info[k] = v
		}
	}
	var missing []string
	for _, f := range files {
		si, ok := info[f.Resolved]
		if !ok || !si.Known {
			missing = append(missing, f.Resolved)
			continue
		}
		f.Mode, f.Owner, f.Group, f.StatSize = si.Mode, si.Owner, si.Group, si.Size
	}
	if len(missing) == 0 {
		return
	}
	shown := missing
	if len(shown) > executablesMaxDiagnostics {
		shown = shown[:executablesMaxDiagnostics]
	}
	for _, p := range shown {
		c.warn(trustfreeze.DiagFieldMissing, execAttrMode, "stat answered nothing for "+p+", so its mode, owner, group and size are unknown")
	}
	if rest := len(missing) - len(shown); rest > 0 {
		c.warn(trustfreeze.DiagFieldMissing, execAttrMode, fmt.Sprintf("%d further program(s) have no file metadata", rest))
	}
	c.degrade(fmt.Sprintf("the file metadata of %d program(s) is unknown", len(missing)))
}

// hash reads every program file and records its digest, or why there is none.
func (c *executablesCollector) hash(files []*ProgramFile) {
	var unreadable, oversize, changed []string
	for i, f := range files {
		if err := c.ctx.Err(); err != nil {
			// The deadline (or a cancellation) ended the capture. Every file
			// from here on was never read, and saying "unreadable" about it
			// would turn a property of THIS RUN into a property of the FILE:
			// the manual defines unreadable as a file this account could not
			// read. The probe is a timeout, which is what every sibling
			// reports for the same cause (routesStatus, privStatus).
			c.notReached(files[i:], err)
			return
		}
		if size, err := strconv.ParseInt(f.StatSize, 10, 64); err == nil && size > ExecutableMaxFileBytes {
			// stat already said it is too big, so the file is not opened at
			// all. The bound is named beside the size, so the diagnostic can
			// be acted on without reading this file.
			f.HashState = HashStateOverSizeLimit
			oversize = append(oversize, fmt.Sprintf("%s has %d bytes, the limit is %d", f.Resolved, size, ExecutableMaxFileBytes))
			c.tooLarge++
			continue
		}
		sum, n, err := c.reader.Hash(c.ctx, f.Resolved, ExecutableMaxFileBytes)
		switch {
		case err == nil:
			f.SHA256, f.HashedBytes, f.HashState = sum, n, HashStateCaptured
			// The size of a program is the number of bytes that produced its
			// digest. Where stat said something else, its answer is older than
			// the digest and the file was written in between; recording stat's
			// number beside this digest would describe a state that never
			// existed.
			hashed := strconv.FormatInt(n, 10)
			if f.StatSize != "" && f.StatSize != hashed {
				changed = append(changed, fmt.Sprintf(
					"%s: stat reported %s bytes and %d were hashed, so the file was written between the two reads; the recorded size is the hashed one",
					f.Resolved, f.StatSize, n))
			}
			f.StatSize = hashed
		case errors.Is(err, ErrExecutableTooLarge):
			f.HashState = HashStateOverSizeLimit
			oversize = append(oversize, fmt.Sprintf("%s is larger than the limit of %d bytes", f.Resolved, ExecutableMaxFileBytes))
			c.tooLarge++
		case errors.Is(err, fs.ErrPermission):
			f.HashState = HashStatePermissionDenied
			unreadable = append(unreadable, f.Resolved+": this account may not read the file, so it has no digest in this bundle")
			c.unreadable++
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// The hash loop checks the context between chunks, so a deadline
			// inside a large file arrives here. This file and everything after
			// it was not read.
			// The same order the tail of this function uses, so the
			// diagnostics of a capture that timed out and one that did not are
			// the same block in the same sequence.
			c.reportHashGaps(DiagExecutableOverSizeLimit, oversize, "program(s) are larger than the size limit and have no digest")
			c.reportHashGaps(DiagExecutableUnreadable, unreadable, "program(s) could not be read and have no digest")
			c.reportHashGaps(DiagExecutableChangedWhileRead, changed, "program(s) changed between the metadata call and the hash")
			c.notReached(files[i:], err)
			return
		default:
			f.HashState = HashStateUnreadable
			unreadable = append(unreadable, f.Resolved+": "+executablesErrorReason(err))
			c.unreadable++
		}
	}
	c.reportHashGaps(DiagExecutableOverSizeLimit, oversize, "program(s) are larger than the size limit and have no digest")
	c.reportHashGaps(DiagExecutableUnreadable, unreadable, "program(s) could not be read and have no digest")
	c.reportHashGaps(DiagExecutableChangedWhileRead, changed, "program(s) changed between the metadata call and the hash")
}

// notReached records the files a capture that ran out of time never read, and
// turns the run into a timeout.
//
// The hash state of these files is not_read, which is a statement about the
// capture: unreadable and permission_denied are statements about a file, and
// this run learned nothing about these bytes at all. The probe status is
// timeout with a timeout ProbeError, so the capture engine and the completeness
// computation see a probe that did not finish rather than a probe that finished
// and found 200 unreadable programs.
func (c *executablesCollector) notReached(files []*ProgramFile, err error) {
	for _, f := range files {
		f.HashState = HashStateNotRead
		f.SHA256 = ""
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Resolved)
	}
	shown := names
	if len(shown) > executablesMaxDiagnostics {
		shown = shown[:executablesMaxDiagnostics]
	}
	for _, n := range shown {
		c.warn(probe.DiagFieldTimeout, execAttrSHA256,
			n+": the capture ran out of time before this program was read, so this bundle says nothing about its bytes")
	}
	if rest := len(names) - len(shown); rest > 0 {
		c.warn(probe.DiagFieldTimeout, execAttrSHA256,
			fmt.Sprintf("%d further program(s) were not read for the same reason", rest))
	}
	c.timedOut = true
	c.degrade(fmt.Sprintf("the capture ran out of time with %d program(s) unread (%v)", len(names), err))
}

// reportHashGaps emits one diagnostic per affected file, capped, plus the
// reason that makes the run partial.
func (c *executablesCollector) reportHashGaps(code string, msgs []string, summary string) {
	if len(msgs) == 0 {
		return
	}
	shown := msgs
	if len(shown) > executablesMaxDiagnostics {
		shown = shown[:executablesMaxDiagnostics]
	}
	for _, m := range shown {
		c.warn(code, execAttrSHA256, m)
	}
	if rest := len(msgs) - len(shown); rest > 0 {
		c.warn(code, execAttrSHA256, fmt.Sprintf("%d further program(s) are affected the same way", rest))
	}
	c.degrade(fmt.Sprintf("%d %s", len(msgs), summary))
}

// resolveOwnership answers the ownership question for every program: the snap
// rule for a path inside a mounted snap, "dpkg -S" for everything else.
func (c *executablesCollector) resolveOwnership(files []*ProgramFile) {
	var ask []*ProgramFile
	for _, f := range files {
		if snap := SnapNameFromPath(f.Resolved); snap != "" {
			f.PackageOwner, f.PackageSource = executablesCapValue(snap), PackageSourceSnapPath
			continue
		}
		ask = append(ask, f)
	}
	if len(ask) == 0 {
		return
	}
	if !c.lookTool(ExecutablesToolDpkg) {
		for _, f := range ask {
			f.PackageOwner, f.PackageSource = PackageOwnerUnknown, PackageSourceDpkgUnavailable
		}
		c.warn(DiagExecutableOwnerUnknown, execAttrPackageOwner, fmt.Sprintf(
			"%s was not found, so the owning package of %d program(s) is unknown; unknown is not the same statement as unowned",
			ExecutablesToolDpkg, len(ask)))
		c.degrade(fmt.Sprintf("the owning package of %d program(s) is unknown", len(ask)))
		return
	}
	c.dpkgVersion = c.s.toolVersion(ExecutablesToolDpkg, []string{"--version"}, "dpkg-version.txt")
	owners := map[string][]string{}
	diversions := map[string]string{}
	asked := map[string]bool{}
	for i := 0; i < len(ask); i += executablesBatch {
		end := i + executablesBatch
		if end > len(ask) {
			end = len(ask)
		}
		args := []string{"-S"}
		for _, f := range ask[i:end] {
			args = append(args, f.Resolved)
			asked[f.Resolved] = true
		}
		cmd := c.runBatched(ExecutablesToolDpkg, args, "command:dpkg -S")
		if cmd.Status != trustfreeze.StatusCaptured && cmd.Status != trustfreeze.StatusFailed {
			for _, f := range ask[i:end] {
				delete(asked, f.Resolved)
			}
			c.warn(netDiagCode(cmd.Status), execAttrPackageOwner, "dpkg -S: "+cmd.Detail)
			continue
		}
		// A path no package owns is reported on stderr with exit 1 while the
		// other lines are still printed (measured on both hosts), so stdout is
		// parsed whatever the exit code says.
		name := fmt.Sprintf("dpkg-search-%02d", i/executablesBatch+1)
		c.s.evidenceIfAny(name+".txt", "stdout:dpkg", cmd.Res.Stdout, cmd.Res.StdoutTruncated)
		c.s.evidenceIfAny(name+".stderr.txt", "stderr:dpkg", cmd.Res.Stderr, cmd.Res.StderrTruncated)
		if cmd.Res.StdoutTruncated {
			c.noteTruncation(cmd, execAttrPackageOwner, "the owning package of the programs beyond the cut was not read")
		}
		found, divert, issues := ParseDpkgSearch(cmd.Res.Stdout.Bytes())
		for _, d := range issues {
			c.warn(d.Code, execAttrPackageOwner, d.Message)
		}
		for k, v := range found {
			owners[k] = append(owners[k], v...)
		}
		for k, v := range divert {
			diversions[k] = v
		}
	}
	var unowned []string
	var unknown int
	for _, f := range ask {
		if by, ok := diversions[f.Resolved]; ok {
			f.DivertedBy = executablesCapValue(by)
		}
		switch pkgs := owners[f.Resolved]; {
		case len(pkgs) > 0:
			sort.Strings(pkgs)
			value, cut := privCapList(slices.Compact(pkgs), executablesMaxValueBytes)
			f.PackageOwner, f.PackageSource = value, PackageSourceDpkg
			if cut {
				c.warn(netDiagVolumeCapped, execAttrPackageOwner,
					fmt.Sprintf("%s is owned by more packages than fit into %d bytes; the recorded list is cut", f.Resolved, executablesMaxValueBytes))
			}
		case asked[f.Resolved]:
			f.PackageOwner, f.PackageSource = PackageOwnerNone, PackageSourceDpkgNoMatch
			unowned = append(unowned, f.Resolved)
		default:
			f.PackageOwner, f.PackageSource = PackageOwnerUnknown, PackageSourceDpkgUnavailable
			unknown++
		}
	}
	// A program nobody owns is a finding and not an error (T-03b B4): it is
	// reported, the probe stays as complete as it was, and the judgement is
	// the policy's.
	if len(unowned) > 0 {
		shown := unowned
		if len(shown) > executablesMaxDiagnostics {
			shown = shown[:executablesMaxDiagnostics]
		}
		for _, p := range shown {
			c.warn(DiagExecutableUnowned, execAttrPackageOwner,
				p+": no package owns this program, according to the package database of this host")
		}
		if rest := len(unowned) - len(shown); rest > 0 {
			c.warn(DiagExecutableUnowned, execAttrPackageOwner, fmt.Sprintf("%d further program(s) are owned by no package", rest))
		}
	}
	if unknown > 0 {
		c.warn(DiagExecutableOwnerUnknown, execAttrPackageOwner, fmt.Sprintf(
			"the owning package of %d program(s) could not be determined; unknown is not the same statement as unowned", unknown))
		c.degrade(fmt.Sprintf("the owning package of %d program(s) is unknown", unknown))
	}
}

// artifacts builds one artifact per program plus the set artifact.
func (c *executablesCollector) artifacts(files []*ProgramFile, start time.Time) []trustfreeze.Artifact {
	prov := trustfreeze.Provenance{
		// The decisive value of a program artifact is its digest, and this
		// build computed it by reading the file; the metadata beside it comes
		// from a command. Method names the read that decides.
		Method:     "file",
		Confidence: trustfreeze.ConfidenceProven,
		Sources:    c.s.sourceList(),
		ObservedAt: trustfreeze.FormatTime(start),
		// The tool version of the only tool whose answer becomes attributes of
		// these artifacts. The versions of systemctl and ss are recorded by
		// linux.systemd and linux.network.listeners, whose parsers this probe
		// reuses; asking again here would cost two processes for a value the
		// bundle already holds.
		ToolVersion: c.statVersion,
	}
	arts := make([]trustfreeze.Artifact, 0, len(files)+1)
	hashed, ownerNone, ownerUnknown := 0, 0, 0
	used := map[string]int{}
	for _, f := range files {
		base := ExecutableArtifactID(f.Resolved)
		id := base
		if n := used[base]; n > 0 {
			id = base + "+" + strconv.Itoa(n+1)
		}
		used[base]++
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			c.warn(probe.DiagArtifactDropped, execAttrPath, "the path of a program yields no valid artifact id")
			c.degrade("a program artifact was dropped")
			continue
		}
		if f.HashState == HashStateCaptured {
			hashed++
		}
		switch f.PackageOwner {
		case PackageOwnerNone:
			ownerNone++
		case PackageOwnerUnknown:
			ownerUnknown++
		}
		attrs := map[string]string{
			execAttrPath:      executablesCapValue(f.Resolved),
			execAttrHashState: f.HashState,
		}
		if f.SHA256 != "" {
			attrs[execAttrSHA256] = f.SHA256
		}
		if f.StatSize != "" {
			attrs[execAttrSize] = f.StatSize
		}
		for k, v := range map[string]string{
			execAttrMode:          f.Mode,
			execAttrOwner:         f.Owner,
			execAttrGroup:         f.Group,
			execAttrPackageOwner:  f.PackageOwner,
			execAttrPackageSource: f.PackageSource,
			execAttrDivertedBy:    f.DivertedBy,
		} {
			if v != "" {
				attrs[k] = v
			}
		}
		if len(f.Requested) > 0 {
			// The path a source named, where a symlink led somewhere else. It
			// is the other half of the finding: the unit still starts
			// /usr/local/bin/x and the bytes are somewhere else.
			value, _ := privCapList(f.Requested, executablesMaxValueBytes)
			attrs[execAttrRequestedPath] = value
		}
		if len(f.Origins) > 0 {
			attrs[execAttrOrigins] = strings.Join(f.Origins, ",")
		}
		if len(f.Units) > 0 {
			value, cut := privCapList(f.Units, executablesMaxValueBytes)
			attrs[execAttrUnits] = value
			if cut {
				attrs[execAttrUnitCount] = strconv.Itoa(len(f.Units))
				c.warn(netDiagVolumeCapped, execAttrUnits, fmt.Sprintf(
					"%s is started by more units than fit into %d bytes; the recorded list is cut and the count says how many there were",
					f.Resolved, executablesMaxValueBytes))
			}
		}
		arts = append(arts, trustfreeze.Artifact{
			ID: id, Type: artifactTypeExecutable, Scope: "system", Source: ExecutablesProbeID,
			// The bytes were read during this capture.
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}

	setAttrs := map[string]string{
		execAttrProgramCount:     strconv.Itoa(len(arts)),
		execAttrHashedCount:      strconv.Itoa(hashed),
		execAttrCandidateCount:   strconv.Itoa(len(c.candidates)),
		execAttrCandidateDropped: strconv.Itoa(c.dropped),
		execAttrRefusedCount:     strconv.Itoa(c.refused),
		execAttrUnreadableCount:  strconv.Itoa(c.unreadable),
		execAttrTooLargeCount:    strconv.Itoa(c.tooLarge),
		execAttrOwnerNoneCount:   strconv.Itoa(ownerNone),
		execAttrOwnerUnknownCnt:  strconv.Itoa(ownerUnknown),
		execAttrFromSystemdCount: strconv.Itoa(c.fromUnit),
		execAttrFromSocketCount:  strconv.Itoa(c.fromSocket),
		execAttrRoots:            strings.Join(ExecutableRoots(), ","),
		execAttrMaxFileBytes:     strconv.FormatInt(ExecutableMaxFileBytes, 10),
		execAttrMaxFiles:         strconv.Itoa(ExecutableMaxFiles),
		execAttrMaxCandidates:    strconv.Itoa(ExecutableMaxCandidates),
		execAttrHashAlgorithm:    "sha256",
		// Always false in this version, and stated rather than implied: this
		// probe never runs "dpkg --verify" and never compares a file with the
		// package's own digest. A reader of the bundle therefore knows that
		// package_owner is the database's claim about the path and not a
		// statement that the bytes are the package's bytes.
		execAttrPackageVerified: privBool(false),
	}
	if c.truncated {
		setAttrs[execAttrListTruncated] = privBool(true)
	}
	if c.statVersion != "" {
		setAttrs[execAttrStatVersion] = executablesCapValue(c.statVersion)
	}
	if c.dpkgVersion != "" {
		setAttrs[execAttrDpkgVersion] = executablesCapValue(c.dpkgVersion)
	}
	setProv := prov
	setProv.Method = "command"
	arts = append(arts, trustfreeze.Artifact{
		ID: ArtifactExecutables, Type: artifactTypeExecutableSet, Scope: "system", Source: ExecutablesProbeID,
		State:       trustfreeze.StateObserved,
		Attributes:  setAttrs,
		Provenance:  setProv,
		Sensitivity: trustfreeze.SensitivityPublic,
	})
	return arts
}

// ---------------------------------------------------------------------------
// Pure parsers and helpers. Everything below works on bytes or strings only,
// so every shape is table tested from the fixtures on any operating system.
// ---------------------------------------------------------------------------

// ParseDpkgSearch reads the stdout of "dpkg -S <path>...".
//
// Three line shapes were measured, on Ubuntu 24.04.1 with dpkg 1.22.6 and on
// Ubuntu 22.04.5 with dpkg 1.21.1, and both releases print all three the same
// way:
//
//	openssh-server: /usr/sbin/sshd
//	libc6-dev:amd64, mesa-vdpau-drivers:amd64, procps: /etc/init.d
//	diversion by libreadline8t64 from: /lib/x86_64-linux-gnu/libhistory.so.8.2
//
// The first is the ordinary answer. The second shows that a path can be owned
// by several packages, comma separated, each possibly with an architecture
// qualifier after a colon; on the trial host one directory path answered with
// 757 package names in one line, which is why the caller caps what it records.
// The third is a diversion record, which names a package and is NOT an
// ownership answer; read as one it would attribute the file to a package name
// that reads "diversion by libreadline8t64 from".
//
// The split is at the first ": " (colon followed by a space). A package name
// carries a colon only as an architecture qualifier, which is never followed by
// a space, so no answer can be split in the wrong place.
//
// A path the database does not know produces NO line here: dpkg writes
// "dpkg-query: no path found matching pattern <path>" to stderr and exits 1
// (measured on both hosts). The absence of a stdout answer is therefore what
// decides that no package owns a path, not the wording of a message, which is
// what keeps this parser valid across releases.
//
// found maps a path to the packages that own it, diversions maps a path to the
// package that diverts it, and issues names the lines this parser could not
// read, by line number and with a stable reason that carries no line content.
func ParseDpkgSearch(b []byte) (found map[string][]string, diversions map[string]string, issues []trustfreeze.Diagnostic) {
	found, diversions = map[string][]string{}, map[string]string{}
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		cut := strings.Index(line, ": ")
		if cut <= 0 {
			issues = append(issues, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   execAttrPackageOwner,
				Message: fmt.Sprintf("dpkg -S line %d: no package and path could be read from it", i+1),
			})
			continue
		}
		left, p := line[:cut], strings.TrimSpace(line[cut+2:])
		if p == "" {
			issues = append(issues, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   execAttrPackageOwner,
				Message: fmt.Sprintf("dpkg -S line %d: the path is empty", i+1),
			})
			continue
		}
		if pkg, ok := dpkgDiversionPackage(left); ok {
			if pkg != "" {
				diversions[p] = pkg
			}
			continue
		}
		var pkgs []string
		for _, name := range strings.Split(left, ",") {
			if n := strings.TrimSpace(name); n != "" {
				pkgs = append(pkgs, n)
			}
		}
		if len(pkgs) == 0 {
			issues = append(issues, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   execAttrPackageOwner,
				Message: fmt.Sprintf("dpkg -S line %d: no package name before the path", i+1),
			})
			continue
		}
		found[p] = append(found[p], pkgs...)
	}
	return found, diversions, issues
}

// dpkgDiversionPackage reports whether the left half of a "dpkg -S" line is a
// diversion record, and names the diverting package where it has one. The two
// measured forms are "diversion by <package> from" and "diversion by <package>
// to"; the form without a package ("local diversion from") is accepted as a
// diversion without a name, so an admin made diversion is never mistaken for
// an owner.
func dpkgDiversionPackage(left string) (pkg string, ok bool) {
	if rest, cut := strings.CutPrefix(left, "diversion by "); cut {
		rest = strings.TrimSuffix(strings.TrimSuffix(rest, " from"), " to")
		return strings.TrimSpace(rest), true
	}
	if strings.HasPrefix(left, "local diversion ") {
		return "", true
	}
	return "", false
}

// executablesRefusalMessage names a file and why it was not read. Every branch
// says what the bundle therefore does not know.
func executablesRefusalMessage(p string, err error) string {
	switch {
	case errors.Is(err, ErrExecutableSymlinkEscape):
		return p + " was not read: it resolves outside the roots this probe may read (" + strings.Join(ExecutableRoots(), ", ") + ")"
	case errors.Is(err, ErrExecutableHomePath):
		return p + " was not read: it lies under a home directory, which this probe never reads"
	case errors.Is(err, ErrExecutableOutsideRoots):
		return p + " was not read: it lies outside the roots this probe may read (" + strings.Join(ExecutableRoots(), ", ") + ")"
	case errors.Is(err, ErrExecutableNotRegular):
		return p + " was not read: it is not a regular file"
	case errors.Is(err, ErrExecutableDeletedTarget):
		return p + " was not read: the file behind the running process is gone, so there is nothing left to hash"
	case errors.Is(err, fs.ErrNotExist):
		return p + " was not read: the path does not exist, although a source of this host names it"
	case errors.Is(err, fs.ErrPermission):
		return p + " was not read: this account may not resolve the path"
	}
	return p + " was not read: " + executablesErrorReason(err)
}

// executablesErrorReason turns an error into a short reason. A path error is
// reduced to its operation and its cause, so a message never repeats a path
// twice and never carries file content.
func executablesErrorReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// executablesCapValue caps one recorded value (playbook L6).
func executablesCapValue(s string) string {
	if len(s) <= executablesMaxValueBytes {
		return s
	}
	return strings.ToValidUTF8(s[:executablesMaxValueBytes], "")
}
