package registry

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
)

// The archive is streamed unchanged; no second archive-sized frame is allocated.
func writeAgentRecord(w io.Writer, h agentRecordHeader, archive, context []byte) error {
	if err := validAgentHeader(h); err != nil {
		return err
	}
	if h.ArchiveBytes != int64(len(archive)) || h.ContextBytes != int64(len(context)) || h.BundleDigest != agentDigest(archive) || h.ContextSHA256 != strings.TrimPrefix(agentDigest(context), "sha256:") {
		return ErrAgentEvidenceInvalid
	}
	header, err := json.Marshal(h)
	if err != nil {
		return ErrAgentEvidenceInvalid
	}
	headerLen := len(header)
	if headerLen < 1 || headerLen > maxAgentHeader {
		return ErrAgentEvidenceInvalid
	}
	var prefix [12]byte
	copy(prefix[:8], agentRecordMagic)
	binary.BigEndian.PutUint32(prefix[8:], uint32(headerLen))
	for _, part := range [][]byte{prefix[:], header, archive, context} {
		for len(part) > 0 {
			n := len(part)
			if n > 64<<10 {
				n = 64 << 10
			}
			written, e := w.Write(part[:n])
			if e != nil {
				return e
			}
			if written != n {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
func validAgentHeader(h agentRecordHeader) error {
	if h.Schema != agentRecordSchema || h.Kind != "agent" || !validAgentName(h.Name) || !agentText(h.Version, 256) || h.ArchiveBytes <= 0 || h.ArchiveBytes > MaxBlobSize || h.ContextBytes <= 0 || h.ContextBytes > maxAgentContext {
		return ErrAgentEvidenceInvalid
	}
	if !strings.HasPrefix(h.BundleDigest, "sha256:") || len(h.BundleDigest) != 71 || strings.ToLower(h.BundleDigest) != h.BundleDigest || len(h.ContextSHA256) != 64 || strings.ToLower(h.ContextSHA256) != h.ContextSHA256 {
		return ErrAgentEvidenceInvalid
	}
	if _, e := hex.DecodeString(h.BundleDigest[7:]); e != nil {
		return ErrAgentEvidenceInvalid
	}
	if _, e := hex.DecodeString(h.ContextSHA256); e != nil {
		return ErrAgentEvidenceInvalid
	}
	return nil
}

// readAgentRecordHeader leaves r positioned at the exact raw archive segment.
// A future reader must reserve its own cumulative byte budget before reading it.
func readAgentRecordHeader(r io.Reader) (agentRecordHeader, error) {
	var h agentRecordHeader
	var prefix [12]byte
	if _, e := io.ReadFull(r, prefix[:]); e != nil {
		return h, ErrAgentEvidenceInvalid
	}
	n := binary.BigEndian.Uint32(prefix[8:])
	if string(prefix[:8]) != agentRecordMagic || n == 0 || n > maxAgentHeader {
		return h, ErrAgentEvidenceInvalid
	}
	raw := make([]byte, int(n))
	if _, e := io.ReadFull(r, raw); e != nil {
		return h, ErrAgentEvidenceInvalid
	}
	obj, e := readAgentJSON(raw, maxAgentHeader)
	if e != nil || len(obj) != 8 {
		return h, ErrAgentEvidenceInvalid
	}
	for _, key := range []string{"schema", "kind", "name", "version", "bundle_digest", "archive_bytes", "context_bytes", "context_sha256"} {
		if _, ok := obj[key]; !ok {
			return h, ErrAgentEvidenceInvalid
		}
	}
	if json.Unmarshal(raw, &h) != nil || validAgentHeader(h) != nil {
		return h, ErrAgentEvidenceInvalid
	}
	return h, nil
}
