package linux

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// Probe identity of linux.ssh (SPEC-0471 TF06-R3).
const (
	SSHProbeID      = "linux.ssh"
	SSHProbeVersion = "1"
)

// Paths and tools of linux.ssh.
const (
	// SSHDConfigPath is the main server configuration file.
	SSHDConfigPath = "/etc/ssh/sshd_config"
	// SSHDConfigDir holds the drop-in configuration files.
	SSHDConfigDir = "/etc/ssh/sshd_config.d"
	// SSHDir is the configuration directory itself.
	SSHDir = "/etc/ssh"
	// sshdExe is the server binary; it is asked for its version and for the
	// effective configuration, never started as a daemon.
	sshdExe = "sshd"
	// getentExe reads the account database for the authorized_keys lookup.
	getentExe = "getent"
	// sshListTool enumerates the configuration directories.
	sshListTool = "ls"
)

// Home roots the authorized_keys lookup may read. Only the exact file
// <home>/.ssh/authorized_keys and its authorized_keys2 sibling are ever
// requested, and the restricted file reader refuses everything outside these
// roots, so an account whose home lies elsewhere is reported as not readable
// instead of being read.
const (
	sshHomeRoot     = "/home"
	sshRootHomeRoot = "/root"
)

// Artifact ids of linux.ssh.
const (
	// ArtifactSSHDeclared is the resolved declared server state.
	ArtifactSSHDeclared = "ssh/sshd/declared"
	// ArtifactSSHEffective is the state sshd itself reports (sshd -T). It
	// exists only when that call succeeded; a refusal is a collection gap,
	// never a promotion of the declared values (playbook L3).
	ArtifactSSHEffective = "ssh/sshd/effective"
	// ArtifactSSHDirectory summarizes /etc/ssh: how many files sit next to the
	// active configuration and how many of them look like a configuration but
	// are not read.
	ArtifactSSHDirectory = "ssh/sshd/directory"
	// ArtifactSSHConfigFilePrefix prefixes one configuration file, for example
	// ssh/sshd/config-file/sshd_config.
	ArtifactSSHConfigFilePrefix = "ssh/sshd/config-file/"
	// ArtifactSSHMatchPrefix prefixes one Match block.
	ArtifactSSHMatchPrefix = "ssh/sshd/match/"
	// ArtifactSSHAuthorizedKeysPrefix prefixes the authorized_keys file of one
	// account, ArtifactSSHAuthorizedKeyPrefix one key inside it.
	ArtifactSSHAuthorizedKeysPrefix = "ssh/authorized-keys/"
	ArtifactSSHAuthorizedKeyPrefix  = "ssh/authorized-key/"
)

// Artifact types of linux.ssh.
const (
	SSHDeclaredType       = "sshd-config"
	SSHEffectiveType      = "sshd-effective"
	SSHConfigFileType     = "sshd-config-file"
	SSHMatchType          = "sshd-match"
	SSHDirectoryType      = "sshd-config-directory"
	SSHAuthorizedKeysType = "authorized-keys-file"
	SSHAuthorizedKeyType  = "authorized-key"
)

// Attribute names of the ssh artifacts.
const (
	sshAttrSourceFiles   = "source_files"
	sshAttrIncludeFiles  = "include_files"
	sshAttrMatchBlocks   = "match_blocks"
	sshAttrCriteria      = "criteria"
	sshAttrKeywords      = "keywords"
	sshAttrEntryCount    = "entry_count"
	sshAttrConfigLike    = "config_like_siblings"
	sshAttrKeyCount      = "key_count"
	sshAttrKeyType       = "key_type"
	sshAttrFingerprint   = "fingerprint"
	sshAttrKeyOptions    = "options"
	sshAttrKeyOptionsCnt = "option_count"
)

// sshDiagEffectiveNotObservable marks the gap that matters most on a bastion:
// the declared configuration was read, but what sshd actually runs with could
// not be observed (SPEC-0471 TF06-R3, playbook L3).
const sshDiagEffectiveNotObservable = "effective_state_not_observable"

// sshDiagIncludeMatchedNothing marks an Include whose pattern named no file
// this capture read. On a stock Ubuntu host the include directory is empty and
// that is the normal case, not a failure: sshd skips such a pattern silently.
// The note exists so that a reader can tell an empty directory from one that
// could not be listed.
const sshDiagIncludeMatchedNothing = "include_matched_nothing"

// sshdRefusalNoHostKeys is the diagnostic an unprivileged "sshd -T" ends with
// on the trial host, recorded byte for byte in
// testdata/ssh/sshd-T-unprivileged.stderr.txt: sshd cannot read the host
// private keys, exits 1 and prints this single line.
const sshdRefusalNoHostKeys = "no hostkeys available"

// sshDeclaredKeywords is the fixed set of keywords the declared and the
// effective artifact record. A stock sshd -T prints about a hundred keywords;
// recording all of them would make every OpenSSH upgrade look like a
// configuration change, so the artifact keeps the ones that decide who may log
// in and how (playbook L6). Every keyword is spelled in lower case, the way
// sshd -T prints it.
var sshDeclaredKeywords = []string{
	"allowagentforwarding", "allowgroups", "allowtcpforwarding", "allowusers",
	"authorizedkeyscommand", "authorizedkeyscommanduser", "authorizedkeysfile",
	"banner", "challengeresponseauthentication", "chrootdirectory",
	"clientaliveinterval", "denygroups", "denyusers", "forcecommand",
	"gatewayports", "gssapiauthentication", "hostbasedauthentication",
	"ignorerhosts", "kbdinteractiveauthentication", "logingracetime",
	"maxauthtries", "maxsessions", "maxstartups", "passwordauthentication",
	"permitemptypasswords", "permitrootlogin", "permittty", "permittunnel",
	"permituserenvironment", "pubkeyauthentication", "strictmodes", "usedns",
	"usepam", "x11forwarding",
}

// sshMultiValueKeywords accumulate: sshd keeps every occurrence instead of the
// first one. Everything else follows the first-obtained-value rule.
var sshMultiValueKeywords = map[string]bool{
	"acceptenv": true, "hostkey": true, "listenaddress": true,
	"port": true, "setenv": true, "subsystem": true,
}

// sshMaxAccounts bounds the authorized_keys lookup, and sshMaxKeysPerAccount
// the keys recorded per account. Reaching a bound is reported, never silent.
const (
	sshMaxAccounts       = 64
	sshMaxKeysPerAccount = 64
	// sshMaxIncludeDepth bounds Include expansion; sshd itself allows one
	// level of nesting, this parser allows a little more and then stops with
	// a diagnostic instead of looping.
	sshMaxIncludeDepth = 8
	// sshSystemAccountUIDMax is the largest uid this probe treats as a system
	// account. Only root and the regular accounts above it are looked at.
	sshSystemAccountUIDMax = 999
	// sshNobodyUID is skipped: it owns no interactive access.
	sshNobodyUID = 65534
)

// SSHAllowedRoots returns the file roots linux.ssh reads.
func SSHAllowedRoots() []string {
	return []string{SSHDir, sshHomeRoot, sshRootHomeRoot}
}

// SSHProbe collects the SSH server state of the host.
//
// Declared versus observed (playbook L3): /etc/ssh/sshd_config and the files
// it includes are the DECLARED state, and they stay declared. "sshd -T" prints
// the state sshd itself resolves, which is the OBSERVED state; it needs to read
// the host private keys, so an unprivileged capture gets a refusal. That is a
// permission_denied with the declared state still recorded, never a declared
// value presented as observed.
//
// Resolution rule for the declared state: sshd_config(5) says "unless noted
// otherwise, for each keyword, the first obtained value will be used". This
// probe implements exactly that rule, so the recorded declared state is the one
// sshd would resolve:
//
//   - an Include is expanded at the position it stands, which is why the
//     drop-in directory that Ubuntu includes in the first lines of the file
//     wins over the same keyword further down;
//   - for a keyword that sshd accumulates (Port, ListenAddress, HostKey,
//     AcceptEnv, SetEnv, Subsystem) every value is kept, in order;
//   - everything after a Match line is conditional. It is NOT part of the
//     global declared state; each Match block becomes an artifact of its own.
//
// What is never recorded: the body or the comment of a public key. An
// authorized_keys entry contributes its key type, its fingerprint (computed in
// Go, the RFC 4716 SHA256 form sshd itself prints) and the NAMES of its
// options; the key material and the free text comment stay out of the bundle
// (playbook L4).
type SSHProbe struct{}

// NewSSHProbe returns the linux.ssh probe.
func NewSSHProbe() *SSHProbe { return &SSHProbe{} }

// Descriptor implements probe.Probe.
func (p *SSHProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                SSHProbeID,
		Version:           SSHProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    30 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides: []string{
			ArtifactSSHAuthorizedKeyPrefix, ArtifactSSHAuthorizedKeysPrefix,
			ArtifactSSHConfigFilePrefix, ArtifactSSHDeclared, ArtifactSSHDirectory,
			ArtifactSSHEffective, ArtifactSSHMatchPrefix,
		},
	}
}

// RequiredTools implements the structural ToolUser interface of the capture
// engine: doctor resolves these through LookPath and never runs one. sshd is
// asked for its version and for the effective configuration; it is never
// started as a daemon.
func (p *SSHProbe) RequiredTools() []string { return []string{getentExe, sshListTool, sshdExe} }

// EvidenceClaims implements probe.EvidenceClaimer.
func (p *SSHProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe. The declared state is a file, so the probe
// runs even where sshd is not installed; a missing sshd costs the effective
// state and is reported per input.
func (p *SSHProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("no sshd configuration source for " + host.GOOS)
	}
	return probe.Supported()
}

// Collect implements probe.Probe.
func (p *SSHProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := newPrivCollector(ctx, cc)
	res := privBaseResult(SSHProbeID, SSHProbeVersion, cc, start)
	if cc.GOOS != "linux" {
		res.Status = trustfreeze.StatusUnsupported
		res.Reason = "no sshd configuration source for " + cc.GOOS
		return res
	}
	// Playbook L7: every tool this probe uses records its version. sshd prints
	// its banner on stderr and exits 0 (testdata ssh/sshd-version.stderr.txt).
	c.recordVersion(sshdExe, []string{"-V"}, privStderr)
	c.recordVersion(sshListTool, []string{"--version"}, privStdout)
	c.recordVersion(getentExe, []string{"--version"}, privStdout)

	var (
		arts   []trustfreeze.Artifact
		states []privState
	)
	declaredArts, declaredState, found := c.collectSSHDeclared()
	arts = append(arts, declaredArts...)
	if found {
		states = append(states, declaredState)
	}
	effectiveArts, effectiveState := c.collectSSHEffective()
	arts = append(arts, effectiveArts...)
	states = append(states, effectiveState)

	keyArts, keyState := c.collectAuthorizedKeys()
	arts = append(arts, keyArts...)
	states = append(states, keyState)

	states = append(states, c.extraStates()...)
	res.Status, res.Reason, res.Error = privStatus(states, "the ssh server state")
	if !found && effectiveState == privUnavailable {
		res.Status = trustfreeze.StatusNotApplicable
		res.Reason = "no " + SSHDConfigPath + " and no sshd on this host"
		res.Error = nil
	}
	return c.finish(res, arts, start)
}

// collectSSHDeclared reads the configuration files and resolves them.
func (c *privCollector) collectSSHDeclared() (arts []trustfreeze.Artifact, st privState, found bool) {
	entries, dirState, dirDetail := c.listDir(SSHDir, "etc-ssh")
	if dirState != privOK {
		c.warn(privStateCode(dirState), SSHDir, dirDetail)
	} else {
		arts = append(arts, c.sshDirectoryArtifact(entries))
	}
	includeEntries, incState, incDetail := c.listDir(SSHDConfigDir, "sshd_config.d")
	if incState != privOK {
		c.warn(privStateCode(incState), SSHDConfigDir, incDetail)
	}

	raw, st, detail := c.readFile(SSHDConfigPath)
	if st != privOK {
		if st == privUnavailable {
			return arts, st, false
		}
		c.warn(privStateCode(st), SSHDConfigPath, detail)
		return arts, st, true
	}
	root := ParseSSHDConfig(SSHDConfigPath, raw)
	arts = append(arts, c.sshConfigFileArtifact(root, raw))
	if red, ok := c.redactFile(SSHDConfigPath, raw); ok {
		c.addEvidence("sshd_config.txt", "file:"+SSHDConfigPath, red, false)
	}

	// Only files the include pattern names are read. The nine
	// sshd_config.backup-* files and the .ucf-dist file next to the active
	// configuration are listed, never parsed: a wider glob would record a
	// state that sshd does not use.
	avail := map[string]SSHDConfigFile{}
	for _, e := range includeEntries {
		if e.IsDir {
			continue
		}
		p := SSHDConfigDir + "/" + e.Name
		b, fst, fdetail := c.readFile(p)
		if fst != privOK {
			c.warn(privStateCode(fst), p, fdetail)
			st = privWorse(st, fst)
			continue
		}
		f := ParseSSHDConfig(p, b)
		avail[p] = f
		arts = append(arts, c.sshConfigFileArtifact(f, b))
	}

	dirs, diags := ExpandSSHDIncludes(root, avail, sshMaxIncludeDepth)
	for _, d := range diags {
		if d.Code == sshDiagIncludeMatchedNothing && incState == privOK && len(includeEntries) == 0 {
			// The include directory was listed and is empty. That is the
			// declared state of a stock host, not a gap (testdata
			// ssh/ls-la-sshd-config-d.txt).
			continue
		}
		c.warn(d.Code, d.Field, d.Message)
	}
	for _, f := range append([]SSHDConfigFile{root}, sshSortedFiles(avail)...) {
		for _, is := range f.Issues {
			c.warn(is.Code, f.Path, is.Message)
			st = privWorse(st, privPartial)
		}
	}
	declared := ResolveSSHD(dirs)
	arts = append(arts, c.sshDeclaredArtifact(declared, root, avail))
	for i, m := range declared.Matches {
		arts = append(arts, c.sshMatchArtifact(i, m))
	}
	return arts, st, true
}

// collectSSHEffective runs "sshd -T". Its refusal is the honest answer of this
// host, not a reason to present the declared state as observed.
func (c *privCollector) collectSSHEffective() ([]trustfreeze.Artifact, privState) {
	r := c.run(sshdExe, "-T")
	switch {
	case r.State != privOK:
		c.warn(privStateCode(r.State), "sshd -T", "sshd -T: "+r.Detail)
		if r.State == privUnavailable {
			c.warn(sshDiagEffectiveNotObservable, ArtifactSSHEffective,
				"sshd is not installed, so the effective server state cannot be observed; the declared state stays declared")
		}
		return nil, r.State
	case r.ExitCode != 0:
		line := privFirstLine(r.Stderr)
		st := privFailed
		if strings.Contains(line, sshdRefusalNoHostKeys) || privLooksDenied(line) {
			// sshd -T reads the host private keys, which are 0600 root:root.
			// Unprivileged it exits 1 with this refusal (testdata
			// ssh/sshd-T-unprivileged.stderr.txt). Trust Freeze never elevates
			// (playbook L2), so this stays a gap.
			st = privPermissionDenied
		}
		c.warn(privStateCode(st), "sshd -T", fmt.Sprintf("sshd -T: exit status %d: %s", r.ExitCode, line))
		c.warn(sshDiagEffectiveNotObservable, ArtifactSSHEffective,
			"the effective server state is not observable with the privilege of this capture; the declared state stays declared")
		return nil, st
	}
	c.addEvidence("sshd-T.txt", "stdout:sshd", r.StdoutData, r.StdoutTruncated)
	c.addSource("command:sshd -T")
	f := ParseSSHDConfig("sshd -T", r.Stdout)
	for _, is := range f.Issues {
		c.warn(is.Code, "sshd -T", is.Message)
	}
	eff := ResolveSSHD(f.Directives)
	attrs := map[string]string{}
	sshApplyKeywords(attrs, eff)
	if len(attrs) == 0 {
		c.warn(trustfreeze.DiagFieldMissing, ArtifactSSHEffective, "sshd -T printed no keyword this probe records")
		return nil, privPartial
	}
	return []trustfreeze.Artifact{c.artifact(ArtifactSSHEffective, SSHEffectiveType, "host",
		trustfreeze.StateObserved, attrs, "command", trustfreeze.ConfidenceProven,
		[]string{"command:sshd -T"}, c.versions[sshdExe], trustfreeze.SensitivityInternal)}, privOK
}

// sshDirectoryArtifact records what sits next to the active configuration.
// Names of backup files are counted, not listed: the count is what changes
// when somebody edits the configuration through a tool that keeps backups.
func (c *privCollector) sshDirectoryArtifact(entries []LsEntry) trustfreeze.Artifact {
	configLike := 0
	for _, e := range entries {
		if e.IsDir || e.Name == privBase(SSHDConfigPath) {
			continue
		}
		if strings.HasPrefix(e.Name, "sshd_config") {
			configLike++
		}
	}
	attrs := map[string]string{
		privAttrPath:      SSHDir,
		sshAttrEntryCount: strconv.Itoa(len(entries)),
		sshAttrConfigLike: strconv.Itoa(configLike),
	}
	return c.artifact(ArtifactSSHDirectory, SSHDirectoryType, "host", trustfreeze.StateObserved,
		attrs, "command", trustfreeze.ConfidenceProven, []string{"command:ls -la " + SSHDir},
		c.versions[sshListTool], trustfreeze.SensitivityInternal)
}

func (c *privCollector) sshConfigFileArtifact(f SSHDConfigFile, raw []byte) trustfreeze.Artifact {
	name := strings.TrimPrefix(f.Path, SSHDir+"/")
	attrs := map[string]string{
		privAttrPath:          f.Path,
		privAttrSize:          strconv.Itoa(len(raw)),
		privAttrContentSHA256: trustfreeze.Digest(raw),
		privAttrReadable:      privBool(true),
		"directives":          strconv.Itoa(len(f.Directives)),
	}
	return c.artifact(ArtifactSSHConfigFilePrefix+name, SSHConfigFileType, "host",
		trustfreeze.StateDeclared, attrs, "file", trustfreeze.ConfidenceProven,
		[]string{"file:" + f.Path}, "", trustfreeze.SensitivityInternal)
}

func (c *privCollector) sshDeclaredArtifact(d SSHDDeclared, root SSHDConfigFile, avail map[string]SSHDConfigFile) trustfreeze.Artifact {
	attrs := map[string]string{}
	sshApplyKeywords(attrs, d)
	files := []string{root.Path}
	sources := []string{"file:" + root.Path}
	for _, f := range sshSortedFiles(avail) {
		files = append(files, f.Path)
		sources = append(sources, "file:"+f.Path)
	}
	attrs[sshAttrSourceFiles] = privJoin(files)
	attrs[sshAttrIncludeFiles] = strconv.Itoa(len(avail))
	attrs[sshAttrMatchBlocks] = strconv.Itoa(len(d.Matches))
	return c.artifact(ArtifactSSHDeclared, SSHDeclaredType, "host", trustfreeze.StateDeclared,
		attrs, "file", trustfreeze.ConfidenceProven, sources, "", trustfreeze.SensitivityInternal)
}

func (c *privCollector) sshMatchArtifact(i int, m SSHDMatch) trustfreeze.Artifact {
	attrs := map[string]string{
		sshAttrCriteria: m.Criteria,
		sshAttrKeywords: privJoin(m.Keywords),
		privAttrFile:    m.File,
		privAttrLine:    strconv.Itoa(m.Line),
	}
	id := ArtifactSSHMatchPrefix + strconv.Itoa(i+1)
	return c.artifact(id, SSHMatchType, "host", trustfreeze.StateDeclared, attrs, "file",
		trustfreeze.ConfidenceProven, []string{"file:" + m.File}, "", trustfreeze.SensitivityInternal)
}

// sshApplyKeywords writes the recorded keyword set into an attribute map.
func sshApplyKeywords(attrs map[string]string, d SSHDDeclared) {
	for _, k := range sshDeclaredKeywords {
		if v, ok := d.Values[k]; ok {
			attrs[k] = v
		}
	}
	for k := range sshMultiValueKeywords {
		if v := d.Multi[k]; len(v) > 0 {
			attrs[k] = privJoin(v)
		}
	}
}

func sshSortedFiles(m map[string]SSHDConfigFile) []SSHDConfigFile {
	out := make([]SSHDConfigFile, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// sshAccount is one local account the authorized_keys lookup considers. The
// GECOS field of the account database, which carries the full name of a
// person, is never read (playbook L4).
type sshAccount struct {
	Name  string
	UID   int
	Home  string
	Shell string
}

// collectAuthorizedKeys records the authorized_keys files this capture can
// actually read. An account whose file cannot be read is counted, so the
// artifact says how much of the picture is missing (playbook L1); its keys are
// never guessed.
func (c *privCollector) collectAuthorizedKeys() ([]trustfreeze.Artifact, privState) {
	accounts, st := c.sshAccounts()
	if st != privOK {
		return nil, st
	}
	var (
		arts       []trustfreeze.Artifact
		unreadable int
		outside    int
	)
	for _, acc := range accounts {
		id := ArtifactSSHAuthorizedKeysPrefix + acc.Name
		if trustfreeze.ValidateArtifactID(id) != nil {
			c.warn(probe.DiagArtifactDropped, id, "account name does not produce a valid artifact id")
			continue
		}
		// Both counters count accounts, not read attempts: the loop below
		// tries two file names per account (F12).
		accOutside, accUnreadable := false, false
		for _, rel := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			fp := acc.Home + "/" + rel
			raw, fst, _ := c.readFile(fp)
			switch fst {
			case privOK:
			case privUnavailable:
				// No such file: this account has no key file, which is a fact,
				// not a gap.
				continue
			case privNotApplicable:
				accOutside = true
				continue
			default:
				// The file exists and this capture may not read it. That is a
				// gap in the key picture, and it becomes an artifact of its
				// own, so the capability resolver and a later diff see it
				// instead of an absence (F4).
				accUnreadable = true
				fileID := id
				if strings.HasSuffix(rel, "2") {
					fileID += "2"
				}
				arts = append(arts, c.unreadableKeysArtifact(fileID, acc, rel))
				continue
			}
			keys, diags := ParseAuthorizedKeys(raw)
			for _, d := range diags {
				c.warn(d.Code, id, d.Message)
			}
			fileID := id
			if strings.HasSuffix(rel, "2") {
				fileID += "2"
			}
			arts = append(arts, c.authorizedKeysArtifact(fileID, acc, rel, len(keys), len(raw)))
			arts = append(arts, c.authorizedKeyArtifacts(acc, rel, keys)...)
		}
		if accOutside {
			outside++
		}
		if accUnreadable {
			unreadable++
		}
	}
	if outside > 0 {
		c.warn(probe.DiagFieldNotApplicable, ArtifactSSHAuthorizedKeysPrefix,
			fmt.Sprintf("%d accounts have a home outside the roots this capture may read; their key files were not opened", outside))
	}
	if unreadable > 0 {
		// Not a failure of the probe: an ordinary account may not read another
		// account's keys. It is a gap and is recorded as one.
		c.warn(probe.DiagFieldPermissionDenied, ArtifactSSHAuthorizedKeysPrefix,
			fmt.Sprintf("%d authorized_keys files exist but could not be read with the privilege of this capture", unreadable))
		return arts, privPermissionDenied
	}
	if outside > 0 {
		return arts, privPartial
	}
	return arts, privOK
}

// unreadableKeysArtifact records an authorized_keys file that exists and was
// refused. It carries no key count: nobody counted them.
func (c *privCollector) unreadableKeysArtifact(id string, acc sshAccount, rel string) trustfreeze.Artifact {
	attrs := map[string]string{
		privAttrAccount:  acc.Name,
		privAttrPath:     rel,
		privAttrReadable: privBool(false),
	}
	return c.artifact(id, SSHAuthorizedKeysType, "user", trustfreeze.StateDeclared, attrs, "file",
		trustfreeze.ConfidenceProven, []string{"file:" + rel}, "", trustfreeze.SensitivityInternal)
}

func (c *privCollector) authorizedKeysArtifact(id string, acc sshAccount, rel string, keys, size int) trustfreeze.Artifact {
	attrs := map[string]string{
		privAttrAccount:  acc.Name,
		privAttrPath:     rel,
		privAttrSize:     strconv.Itoa(size),
		privAttrReadable: privBool(true),
		sshAttrKeyCount:  strconv.Itoa(keys),
	}
	return c.artifact(id, SSHAuthorizedKeysType, "user", trustfreeze.StateDeclared, attrs, "file",
		trustfreeze.ConfidenceProven, []string{"file:" + rel}, "", trustfreeze.SensitivityInternal)
}

func (c *privCollector) authorizedKeyArtifacts(acc sshAccount, rel string, keys []AuthorizedKey) []trustfreeze.Artifact {
	var out []trustfreeze.Artifact
	for i, k := range keys {
		if i >= sshMaxKeysPerAccount {
			c.warn(probe.DiagFieldFailed, ArtifactSSHAuthorizedKeyPrefix+acc.Name,
				fmt.Sprintf("more than %d keys; the rest is not recorded", sshMaxKeysPerAccount))
			break
		}
		attrs := map[string]string{
			privAttrAccount:      acc.Name,
			privAttrPath:         rel,
			privAttrLine:         strconv.Itoa(k.Line),
			sshAttrKeyType:       k.Type,
			sshAttrFingerprint:   k.Fingerprint,
			sshAttrKeyOptions:    privJoin(k.Options),
			sshAttrKeyOptionsCnt: strconv.Itoa(len(k.Options)),
		}
		id := ArtifactSSHAuthorizedKeyPrefix + acc.Name + "/" + k.Slug
		out = append(out, c.artifact(id, SSHAuthorizedKeyType, "user", trustfreeze.StateDeclared,
			attrs, "file", trustfreeze.ConfidenceProven, []string{"file:" + rel}, "",
			trustfreeze.SensitivityInternal))
	}
	return out
}

// sshDiagAccountsSkipped names the accounts the authorized_keys lookup did
// not open a file for. A skipped account is a gap in the key picture, so it
// is counted and reported instead of dropped silently (F6).
const sshDiagAccountsSkipped = "accounts_not_examined"

// sshNonLoginShells are the shells that end a session instead of starting
// one. An account with one of them cannot be logged into, so an
// authorized_keys file under its home grants nothing. Everything else counts
// as a login shell, including an empty field, which the kernel reads as
// /bin/sh.
var sshNonLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/usr/bin/nologin": true,
	"/bin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/dev/null": true, "/nonexistent": true, "/bin/sync": true,
}

// sshLoginShell reports whether the account can start a session with shell.
func sshLoginShell(shell string) bool {
	return !sshNonLoginShells[strings.TrimSpace(shell)]
}

// sshRealHome reports whether home is a directory an authorized_keys file can
// live in. Debian gives a service account /nonexistent, and there is nothing
// to look for there.
func sshRealHome(home string) bool {
	switch home {
	case "", "/", "/nonexistent":
		return false
	}
	return strings.HasPrefix(home, "/")
}

// sshAccounts asks getent for the local accounts and keeps the ones an
// authorized_keys file can grant access to: root, every account above the
// system range, and a system account that has a real home and a login shell,
// which is what "adduser --system" leaves behind for an automation account on
// a bastion (F6). Every other account is counted and reported, so the gap is
// visible. The GECOS field is never read.
func (c *privCollector) sshAccounts() ([]sshAccount, privState) {
	r := c.run(getentExe, "passwd")
	switch {
	case r.State != privOK:
		c.warn(privStateCode(r.State), "getent passwd", "getent passwd: "+r.Detail)
		return nil, r.State
	case r.ExitCode != 0:
		c.warn(probe.DiagFieldFailed, "getent passwd", fmt.Sprintf("getent passwd: exit status %d", r.ExitCode))
		return nil, privFailed
	}
	c.addSource("command:getent passwd")
	accounts := parsePasswdAccounts(r.Stdout)
	out := make([]sshAccount, 0, len(accounts))
	skipped := 0
	for _, a := range accounts {
		// root and every account above the system range are interactive by
		// their uid; a system account earns the lookup through its shell.
		interactive := a.UID == 0 || (a.UID > sshSystemAccountUIDMax && a.UID != sshNobodyUID)
		switch {
		case sshRealHome(a.Home) && (interactive || sshLoginShell(a.Shell)):
			out = append(out, a)
		default:
			skipped++
		}
	}
	if skipped > 0 {
		c.warn(sshDiagAccountsSkipped, ArtifactSSHAuthorizedKeysPrefix, fmt.Sprintf(
			"%d of %d accounts were not examined: they have no home this capture can look in, or no shell that can start a session",
			skipped, len(accounts)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > sshMaxAccounts {
		c.warn(probe.DiagFieldFailed, ArtifactSSHAuthorizedKeysPrefix,
			fmt.Sprintf("%d accounts, only the first %d are looked at", len(out), sshMaxAccounts))
		out = out[:sshMaxAccounts]
	}
	return out, privOK
}

// parsePasswdAccounts reads the "getent passwd" output and keeps the name, the
// uid and the home directory of every account. The GECOS field, which carries
// the full name of a person, is deliberately not returned (playbook L4). It is
// pure: bytes in, accounts out.
func parsePasswdAccounts(b []byte) []sshAccount {
	var out []sshAccount
	for _, line := range privLines(b) {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		out = append(out, sshAccount{Name: fields[0], UID: uid, Home: fields[5], Shell: fields[6]})
	}
	return out
}

// SSHDDirective is one keyword of a configuration file, in the order it was
// read.
type SSHDDirective struct {
	// Keyword is the lower case keyword; Raw keeps the spelling of the file.
	Keyword string
	Raw     string
	Value   string
	File    string
	Line    int
	// Match is the index of the Match block this directive belongs to, or -1
	// for the global scope.
	Match int
}

// SSHDConfigFile is one parsed configuration file.
type SSHDConfigFile struct {
	Path       string
	Directives []SSHDDirective
	// Comments counts the comment lines.
	Comments int
	Issues   []trustfreeze.Diagnostic
}

// SSHDMatch is one Match block: its criteria and the keywords it sets.
type SSHDMatch struct {
	Criteria string
	File     string
	Line     int
	Keywords []string
}

// SSHDDeclared is the resolved state of a directive list.
type SSHDDeclared struct {
	// Values holds the first obtained value of every single valued keyword.
	Values map[string]string
	// Origin names "<file>:<line>" of the winning occurrence.
	Origin map[string]string
	// Multi holds every value of an accumulating keyword, in order.
	Multi map[string][]string
	// Matches are the conditional blocks, in order.
	Matches []SSHDMatch
}

// ParseSSHDConfig parses one sshd configuration file or the output of
// "sshd -T", which has the same shape. It is pure and never fails: a line it
// cannot read becomes an issue with its position, never with its content.
//
// A comment is a line whose first non blank character is "#" (sshd_config(5):
// "empty lines and lines starting with a hash mark are comments"). A keyword
// is separated from its value by blanks or by an equals sign.
func ParseSSHDConfig(path string, b []byte) SSHDConfigFile {
	f := SSHDConfigFile{Path: path}
	// match counts the Match blocks of this file; -1 is the global scope.
	match := -1
	for i, raw := range privLines(b) {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			f.Comments++
			continue
		}
		key, value := sshSplitDirective(line)
		if key == "" {
			f.Issues = append(f.Issues, trustfreeze.Diagnostic{
				Code:    privDiagRecordUnparsed,
				Message: fmt.Sprintf("line %d: no keyword", i+1),
			})
			continue
		}
		lower := strings.ToLower(key)
		// A Match line is kept as a directive of its own: the resolver needs
		// it in the stream to know where a conditional block begins, which
		// survives include expansion across files.
		if lower == sshMatchKeyword {
			match++
		}
		f.Directives = append(f.Directives, SSHDDirective{
			Keyword: lower, Raw: key, Value: value, File: path, Line: i + 1, Match: match,
		})
	}
	return f
}

// sshMatchKeyword begins a conditional block.
const sshMatchKeyword = "match"

// sshSplitDirective splits "Keyword value", "Keyword=value" and
// "Keyword = value" into the keyword and the value.
func sshSplitDirective(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	key := line[:i]
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	return key, strings.TrimSpace(rest)
}

// ExpandSSHDIncludes returns the directives of root with every Include
// replaced, at the position the Include stands, by the directives of the files
// that match it. avail holds the files that were read, keyed by absolute path;
// a pattern that matches nothing yields a diagnostic, the way sshd silently
// skips a glob that matches nothing. It is pure: no file system.
func ExpandSSHDIncludes(root SSHDConfigFile, avail map[string]SSHDConfigFile, maxDepth int) ([]SSHDDirective, []trustfreeze.Diagnostic) {
	var diags []trustfreeze.Diagnostic
	seen := map[string]bool{root.Path: true}
	var walk func(f SSHDConfigFile, depth int) []SSHDDirective
	walk = func(f SSHDConfigFile, depth int) []SSHDDirective {
		var out []SSHDDirective
		for _, d := range f.Directives {
			if d.Keyword != "include" {
				out = append(out, d)
				continue
			}
			if depth >= maxDepth {
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    privDiagRecordUnparsed,
					Field:   f.Path,
					Message: fmt.Sprintf("line %d: include nesting deeper than %d is not expanded", d.Line, maxDepth),
				})
				continue
			}
			matched := 0
			for _, pattern := range strings.Fields(d.Value) {
				if !strings.HasPrefix(pattern, "/") {
					pattern = SSHDir + "/" + pattern
				}
				for _, p := range sshSortedPaths(avail) {
					ok, err := path.Match(pattern, p)
					if err != nil || !ok || seen[p] {
						continue
					}
					seen[p] = true
					matched++
					out = append(out, walk(avail[p], depth+1)...)
				}
			}
			if matched == 0 {
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    sshDiagIncludeMatchedNothing,
					Field:   f.Path,
					Message: fmt.Sprintf("line %d: the include pattern matched no file this capture read", d.Line),
				})
			}
		}
		return out
	}
	return walk(root, 0), diags
}

func sshSortedPaths(m map[string]SSHDConfigFile) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ResolveSSHD applies the sshd resolution rule to a directive list: the first
// obtained value of a keyword wins, an accumulating keyword keeps every value,
// and a directive inside a Match block belongs to that block only, never to the
// global state. It is pure.
func ResolveSSHD(dirs []SSHDDirective) SSHDDeclared {
	d := SSHDDeclared{Values: map[string]string{}, Origin: map[string]string{}, Multi: map[string][]string{}}
	cur := -1
	for _, dir := range dirs {
		switch {
		case dir.Keyword == sshMatchKeyword:
			d.Matches = append(d.Matches, SSHDMatch{Criteria: dir.Value, File: dir.File, Line: dir.Line})
			cur = len(d.Matches) - 1
			continue
		case dir.Match < 0:
			// A directive of the global scope of its file ends the block of
			// an included file, which is where sshd ends it too.
			cur = -1
		case cur >= 0:
			d.Matches[cur].Keywords = privAppendUnique(d.Matches[cur].Keywords, dir.Keyword)
			continue
		}
		if sshMultiValueKeywords[dir.Keyword] {
			d.Multi[dir.Keyword] = append(d.Multi[dir.Keyword], dir.Value)
			continue
		}
		if _, seen := d.Values[dir.Keyword]; seen {
			continue
		}
		d.Values[dir.Keyword] = dir.Value
		d.Origin[dir.Keyword] = dir.File + ":" + strconv.Itoa(dir.Line)
	}
	for i := range d.Matches {
		sort.Strings(d.Matches[i].Keywords)
	}
	return d
}

// AuthorizedKey is one entry of an authorized_keys file, reduced to what may
// be recorded: the key type, the fingerprint and the option names. The key
// body and the free text comment never leave the parser (playbook L4).
type AuthorizedKey struct {
	Line int
	// Type is the algorithm name of the key, for example "ssh-ed25519".
	Type string
	// Fingerprint is the RFC 4716 SHA256 form sshd itself prints:
	// "SHA256:" followed by the unpadded base64 of the SHA-256 of the key
	// blob.
	Fingerprint string
	// Slug is the first eight bytes of the same digest in hex. It is the
	// artifact id suffix, because a fingerprint carries characters an id may
	// not have.
	Slug string
	// Options are the NAMES of the key options, sorted and without their
	// values: a command= or environment= value can carry a path or a secret.
	Options []string
}

// ParseAuthorizedKeys reads an authorized_keys file. It is pure and never
// returns key material: for every entry it computes the fingerprint in Go and
// keeps the algorithm name and the option names only.
//
// The key inside a line is found by decoding: the entry is the first token
// whose successor decodes as a key blob that names exactly that algorithm.
// That works whatever options precede it, including options with blanks inside
// quotes, and it rejects a line whose base64 is not a key.
func ParseAuthorizedKeys(b []byte) ([]AuthorizedKey, []trustfreeze.Diagnostic) {
	var (
		out   []AuthorizedKey
		diags []trustfreeze.Diagnostic
	)
	for i, raw := range privLines(b) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := sshTokens(line)
		found := false
		for t := 0; t+1 < len(tokens); t++ {
			blob, err := base64.StdEncoding.DecodeString(tokens[t+1].text)
			if err != nil {
				continue
			}
			alg, ok := sshBlobAlgorithm(blob)
			if !ok || alg != tokens[t].text {
				continue
			}
			sum := sha256.Sum256(blob)
			out = append(out, AuthorizedKey{
				Line:        i + 1,
				Type:        alg,
				Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
				Slug:        hex.EncodeToString(sum[:8]),
				Options:     ParseAuthorizedKeyOptions(line[:tokens[t].start]),
			})
			found = true
			break
		}
		if !found {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    privDiagRecordUnparsed,
				Message: fmt.Sprintf("line %d: no public key in this entry", i+1),
			})
		}
	}
	return out, diags
}

// sshBlobAlgorithm reads the algorithm name from the head of a key blob: a
// four byte big endian length followed by that many bytes.
func sshBlobAlgorithm(blob []byte) (string, bool) {
	const maxName = 64
	if len(blob) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if n == 0 || n > maxName || int(n) > len(blob)-4 {
		return "", false
	}
	name := string(blob[4 : 4+n])
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x21 || c > 0x7e {
			return "", false
		}
	}
	return name, true
}

// ParseAuthorizedKeyOptions returns the NAMES of the options in front of a
// key, sorted and without duplicates. A value is dropped on purpose: a
// command= option carries a command line and an environment= option carries a
// value, and neither belongs in a bundle (playbook L4).
func ParseAuthorizedKeyOptions(s string) []string {
	var (
		out    []string
		cur    strings.Builder
		quoted bool
		escape bool
	)
	flush := func() {
		name := strings.TrimSpace(cur.String())
		cur.Reset()
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			out = privAppendUnique(out, name)
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case escape:
			escape = false
		case ch == '\\' && quoted:
			escape = true
		case ch == '"':
			quoted = !quoted
		case ch == ',' && !quoted:
			flush()
			continue
		}
		cur.WriteByte(ch)
	}
	flush()
	sort.Strings(out)
	return out
}

// sshToken is one whitespace separated token with its byte offset.
type sshToken struct {
	text  string
	start int
}

func sshTokens(s string) []sshToken {
	var out []sshToken
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i > start {
			out = append(out, sshToken{text: s[start:i], start: start})
		}
	}
	return out
}

// privAppendUnique appends v when it is not already in list.
func privAppendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// privWorse returns the more serious of two states, using the precedence of
// privStatus.
func privWorse(a, b privState) privState {
	rank := map[privState]int{
		privOK: 0, privNotApplicable: 0, privPartial: 1, privFailed: 1,
		privUnavailable: 2, privTimeout: 3, privPermissionDenied: 4,
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// privBase returns the last element of a slash separated path.
func privBase(p string) string { return path.Base(p) }
