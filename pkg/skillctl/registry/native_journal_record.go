package registry

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

const (
	nativeJournalHeaderMax   = 16 << 10
	nativeJournalEvidenceMax = 1 << 20
	nativeJournalRecordMax   = 16 + nativeJournalHeaderMax + nativeJournalEvidenceMax
	nativeJournalLock        = "lock"
	nativeJournalState       = "state.record"
	nativeJournalSchema      = "m3c.native-mutation-history/v1"
	nativeJournalMagic       = "M3CNH01\n"
)

type nativeJournalRecord struct {
	Schema             string    `json:"schema"`
	HistoryAuthorityID string    `json:"history_authority_id"`
	Registry           string    `json:"logical_registry"`
	Scope              string    `json:"authority_scope"`
	Tenant             *string   `json:"tenant_scope"`
	Epoch              int64     `json:"epoch"`
	IssuedAt           time.Time `json:"issued_at"`
	LastSeen           time.Time `json:"last_seen"`
	EvidenceDigest     string    `json:"evidence_sha256"`
	EvidenceLength     int       `json:"evidence_length"`
}

func (r nativeJournalRecord) status() NativeJournalStatus {
	return NativeJournalStatus{r.HistoryAuthorityID, r.EvidenceDigest, r.Epoch, r.IssuedAt, r.LastSeen}
}
func (j *NativeJournal) newRecord(e *nativeAuthenticatedEvidence, now time.Time) nativeJournalRecord {
	return nativeJournalRecord{nativeJournalSchema, j.selection.authority.historyID, j.selection.authority.registry, "key-and-tenant", j.selection.authority.tenant, e.epoch, e.issued, now.UTC(), agentDigest(e.raw)[7:], len(e.raw)}
}
func sameNativeRecord(a, b nativeJournalRecord) bool {
	return a.status() == b.status() && a.Schema == b.Schema && a.Registry == b.Registry && a.Scope == b.Scope && a.EvidenceLength == b.EvidenceLength && ((a.Tenant == nil && b.Tenant == nil) || (a.Tenant != nil && b.Tenant != nil && *a.Tenant == *b.Tenant))
}
func nativeJournalHeader(raw []byte) (r nativeJournalRecord, err error) {
	if len(raw) == 0 || len(raw) > nativeJournalHeaderMax {
		return r, ErrNativeHistoryInvalid
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	for n := 0; ; n++ {
		_, e := tokens.Token()
		if e == io.EOF {
			break
		}
		if e != nil || n >= 4096 {
			return r, ErrNativeHistoryInvalid
		}
	}
	object, e := readAgentJSON(raw, nativeJournalHeaderMax)
	if e != nil || len(object) != 10 {
		return r, ErrNativeHistoryInvalid
	}
	for _, key := range []string{"schema", "history_authority_id", "logical_registry", "authority_scope", "tenant_scope", "epoch", "issued_at", "last_seen", "evidence_sha256", "evidence_length"} {
		if _, ok := object[key]; !ok {
			return r, ErrNativeHistoryInvalid
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil {
		return r, ErrNativeHistoryInvalid
	}
	if r.Schema != nativeJournalSchema || !nativeSHA(r.HistoryAuthorityID) || !nativeSHA(r.EvidenceDigest) || !agentText(r.Registry, 8192) || r.Scope != "key-and-tenant" || r.Epoch < 1 || r.IssuedAt.IsZero() || r.LastSeen.IsZero() || r.LastSeen.Before(r.IssuedAt) || r.EvidenceLength < 1 || r.EvidenceLength > nativeJournalEvidenceMax {
		return r, ErrNativeHistoryInvalid
	}
	if r.Tenant != nil && !agentText(*r.Tenant, 8192) {
		return r, ErrNativeHistoryInvalid
	}
	for key, t := range map[string]time.Time{"issued_at": r.IssuedAt, "last_seen": r.LastSeen} {
		if object[key] != t.UTC().Format(time.RFC3339Nano) {
			return r, ErrNativeHistoryInvalid
		}
	}
	return r, nil
}
func (l *nativeJournalLease) load(ctx context.Context) (r nativeJournalRecord, evidence *nativeAuthenticatedEvidence, err error) {
	if err = nativeJournalContext(ctx); err != nil {
		return r, nil, err
	}
	if err = l.validate(); err != nil {
		return r, nil, err
	}
	if err = l.checkRecordIdentity(); err != nil {
		return r, nil, err
	}
	dir := l.dirs[len(l.dirs)-1]
	f, err := openNativeJournalFile(dir, nativeJournalState, nativeJournalRecordMax, os.O_RDONLY)
	if err != nil {
		if errors.Is(err, ErrNativeHistoryInvalid) || errors.Is(err, os.ErrNotExist) {
			return r, nil, nativeJournalFail(ErrNativeHistoryInvalid, err)
		}
		return r, nil, nativeJournalFail(ErrNativePersistence, err)
	}
	defer func() {
		if closeErr := l.journal.ops.close(f); closeErr != nil {
			err = errors.Join(err, nativeJournalFail(ErrNativePersistence, closeErr))
		}
		if err != nil {
			evidence = nil
			err = nativeJournalPublic(err)
		}
	}()
	var prefix [16]byte
	if _, err = io.ReadFull(f, prefix[:]); err != nil {
		return r, nil, ErrNativeHistoryInvalid
	}
	if string(prefix[:8]) != nativeJournalMagic {
		return r, nil, ErrNativeHistoryInvalid
	}
	headerLength := binary.BigEndian.Uint32(prefix[8:12])
	evidenceLength := binary.BigEndian.Uint32(prefix[12:16])
	if headerLength < 1 || headerLength > nativeJournalHeaderMax || evidenceLength < 1 || evidenceLength > nativeJournalEvidenceMax {
		return r, nil, ErrNativeHistoryInvalid
	}
	header := make([]byte, int(headerLength))
	if _, err = io.ReadFull(f, header); err != nil {
		return r, nil, ErrNativeHistoryInvalid
	}
	r, err = nativeJournalHeader(header)
	if err != nil {
		return r, nil, err
	}
	raw := make([]byte, int(evidenceLength))
	for offset := 0; offset < len(raw); {
		if err = nativeJournalContext(ctx); err != nil {
			return r, nil, err
		}
		end := offset + 32768
		if end > len(raw) {
			end = len(raw)
		}
		var n int
		n, err = io.ReadFull(f, raw[offset:end])
		if err != nil {
			return r, nil, ErrNativeHistoryInvalid
		}
		offset += n
	}
	var trailing [1]byte
	n, tailErr := f.Read(trailing[:])
	if n != 0 || tailErr != io.EOF {
		return r, nil, ErrNativeHistoryInvalid
	}
	if int(evidenceLength) != r.EvidenceLength || agentDigest(raw)[7:] != r.EvidenceDigest {
		return r, nil, ErrNativeHistoryInvalid
	}
	a := l.journal.selection.authority
	if r.HistoryAuthorityID != a.historyID || r.Registry != a.registry || ((r.Tenant == nil) != (a.tenant == nil)) || (r.Tenant != nil && *r.Tenant != *a.tenant) {
		return r, nil, ErrNativeHistoryInvalid
	}
	evidence, err = authenticateNativeEvidence(raw, a)
	if err != nil || r.Epoch != evidence.epoch || !r.IssuedAt.Equal(evidence.issued) {
		return r, nil, ErrNativeHistoryInvalid
	}
	if err = l.validate(); err != nil {
		return r, nil, err
	}
	current, e := dir.root.Lstat(nativeJournalState)
	held, he := f.Stat()
	if e != nil || he != nil || !os.SameFile(current, held) {
		return r, nil, ErrNativeHistoryInvalid
	}
	if err = nativeJournalCheckOpened(f); err != nil {
		return r, nil, err
	}
	if err = nativeJournalPermissions(dir.path+string(os.PathSeparator)+nativeJournalState, current, false); err != nil {
		return r, nil, err
	}
	return r, evidence, nativeJournalContext(ctx)
}
func (l *nativeJournalLease) publish(ctx context.Context, r nativeJournalRecord, evidence *nativeAuthenticatedEvidence) (err error) {
	if err = nativeJournalContext(ctx); err != nil {
		return err
	}
	if err = l.validate(); err != nil {
		return err
	}
	// Precharge worst-case JSON escaping before encoding the small header.
	size := 512
	for _, v := range []string{r.Schema, r.HistoryAuthorityID, r.Registry, r.Scope, r.EvidenceDigest} {
		if len(v) > 8192 || len(v) > (nativeJournalHeaderMax-size)/6 {
			return ErrNativeHistoryInvalid
		}
		size += 6 * len(v)
	}
	if r.Tenant != nil {
		if len(*r.Tenant) > 8192 || len(*r.Tenant) > (nativeJournalHeaderMax-size)/6 {
			return ErrNativeHistoryInvalid
		}
	}
	header, err := json.Marshal(r)
	if err != nil {
		return ErrNativeHistoryInvalid
	}
	headerLength := len(header)
	if headerLength < 1 || headerLength > nativeJournalHeaderMax {
		return ErrNativeHistoryInvalid
	}
	evidenceLength := len(evidence.raw)
	if evidenceLength < 1 || evidenceLength > nativeJournalEvidenceMax {
		return ErrNativeHistoryInvalid
	}
	if _, err = nativeJournalHeader(header); err != nil {
		return err
	}
	// Any failed write/flush/replace leaves this lease terminal.
	defer func() {
		if err != nil {
			l.poisoned = true
			err = nativeJournalFail(ErrNativePersistence, err)
		}
	}()
	dir := l.dirs[len(l.dirs)-1]
	if err = l.checkRecordIdentity(); err != nil {
		return err
	}
	if err = validateNativeJournalOptional(dir, nativeJournalState, nativeJournalRecordMax); err != nil {
		return err
	}
	name, err := nativeJournalTempName()
	if err != nil {
		return err
	}
	f, err := dir.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, l.journal.ops.close(f))
		}
		if e := dir.root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}()
	if err = nativeJournalSecure(dir.path + string(os.PathSeparator) + name); err != nil {
		return err
	}
	var prefix [16]byte
	copy(prefix[:8], nativeJournalMagic)
	binary.BigEndian.PutUint32(prefix[8:12], uint32(headerLength))
	binary.BigEndian.PutUint32(prefix[12:16], uint32(evidenceLength))
	for _, chunk := range [][]byte{prefix[:], header, evidence.raw} {
		for len(chunk) > 0 {
			if err = nativeJournalContext(ctx); err != nil {
				return err
			}
			n := len(chunk)
			if n > 32768 {
				n = 32768
			}
			written, e := l.journal.ops.write(f, chunk[:n])
			if e != nil {
				return e
			}
			if written != n {
				return io.ErrShortWrite
			}
			chunk = chunk[n:]
		}
	}
	if err = l.journal.ops.sync(f); err != nil {
		return err
	}
	stagedInfo, statErr := f.Stat()
	if statErr != nil {
		return statErr
	}
	if err = nativeJournalCheckOpened(f); err != nil {
		return err
	}
	err = l.journal.ops.close(f)
	closed = true
	if err != nil {
		return err
	}
	if err = nativeJournalContext(ctx); err != nil {
		return err
	}
	if err = l.validate(); err != nil {
		return err
	}
	if err = l.checkRecordIdentity(); err != nil {
		return err
	}
	if err = validateNativeJournalOptional(dir, nativeJournalState, nativeJournalRecordMax); err != nil {
		return err
	}
	stagedCurrent, statErr := dir.root.Lstat(name)
	if statErr != nil || !nativeJournalOrdinary(stagedCurrent, false) || !os.SameFile(stagedInfo, stagedCurrent) {
		return ErrNativeHistoryInvalid
	}
	if err = validateNativeJournalOptional(dir, name, nativeJournalRecordMax); err != nil {
		return err
	}
	if err = l.journal.ops.replace(dir.path+string(os.PathSeparator)+name, dir.path+string(os.PathSeparator)+nativeJournalState); err != nil {
		return err
	}
	if err = l.journal.ops.syncDir(dir.path); err != nil {
		return err
	}
	if err = nativeJournalContext(ctx); err != nil {
		return err
	}
	l.stateInfo, err = dir.root.Lstat(nativeJournalState)
	if err != nil || !nativeJournalOrdinary(l.stateInfo, false) {
		return ErrNativeHistoryInvalid
	}
	copyRecord := r
	l.history = &copyRecord
	l.poisoned = false
	return nil
}
