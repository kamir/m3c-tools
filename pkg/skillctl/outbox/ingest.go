// ingest.go — the SPEC-0317 (P1) KafShield ingest CLIENT contract.
//
// The sync agent (cmd/skillctl/sync_cmds.go) drains audit_events over HTTPS to
// this endpoint. The contract's load-bearing rule (R-5.3 / AC-4) is the ACK
// shape: the server acknowledges each accepted event_id with a SIGNED
// durable-seq — a monotonic sequence number counter-signed over the canonical
// (log_id, event_id, durable_seq) message with the ingest key. The client marks
// a row synced ONLY on a valid signed durable-seq; a bare-2xx (an in-memory stub
// that returns 200 with no signed seq) does NOT mark rows synced. This half is
// fully testable at P1 against a contract double (httptest); the assertion that
// the real backend's durable-seq reflects Kafka persistence is the P3 gate.
//
// HTTPS-only (R-5.2): PostBatch refuses any non-https endpoint. The decision to
// tolerate a self-signed cert (InsecureSkipVerify) lives in the CALLER's
// http.Client and is gated to loopback there — prod endpoints never inherit it.
//
// Transport auth (R-5.2) is the SPEC-0127 device token as a bearer, NOT the
// shared X-API-KEY. The client sends NO authorization-bearing tenant field:
// tenant is derived SERVER-side from the token→tenant binding (R-9.2 / AC-12).
package outbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// IngestPath is the enforcement-events ingest route (R-5.3). Appended to the
// configured endpoint base.
const IngestPath = "/api/skills/enforcement/events"

// durableSeqDomain is the domain-separation tag for the signed durable-seq ack
// message. It is DISTINCT from the invocation_event_v1 canonical (event.go): the
// ack is the ingest's counter-signature, a different signed-message family. This
// is NOT a new audit-event vocabulary — event_id / the record canonical are
// unchanged.
const durableSeqDomain = "durable-seq-v1"

// CanonicalDurableSeq is the exact byte message the ingest signs (and the client
// re-verifies) for one durable-seq ack. Domain-separated first line, LF-framed,
// fixed field order, trailing LF — the same discipline as the record canonical.
// The contract double MUST sign these exact bytes.
//
//	durable-seq-v1
//	log_id=<...>
//	event_id=<...>
//	durable_seq=<int>
func CanonicalDurableSeq(logID, eventID string, seq int64) []byte {
	var b strings.Builder
	b.WriteString(durableSeqDomain)
	b.WriteByte('\n')
	b.WriteString("log_id=" + logID + "\n")
	b.WriteString("event_id=" + eventID + "\n")
	b.WriteString("durable_seq=" + strconv.FormatInt(seq, 10) + "\n")
	return []byte(b.String())
}

// IngestBatch is the POST body. Records are the EXACT signed InvocationRecord
// bytes (payload_json), embedded verbatim as raw JSON so the server re-verifies
// the same bytes the device signed — no re-marshalling, no field reordering.
type IngestBatch struct {
	Records     []json.RawMessage `json:"records"`
	ClientEpoch int64             `json:"client_epoch"`
}

// DurableAck is one per-event acknowledgement. A VALID ack (VerifyAck true) is
// the ONLY thing that lets the client mark a row synced.
type DurableAck struct {
	EventID    string `json:"event_id"`
	DurableSeq int64  `json:"durable_seq"`
	SeqSigB64  string `json:"seq_sig_b64"`
}

// IngestResponse is the ack envelope. A response with an empty Acks slice (or
// acks that fail VerifyAck) is a bare-2xx: accepted at the HTTP layer but NOT
// durably acknowledged, so nothing is marked synced.
type IngestResponse struct {
	Acks []DurableAck `json:"acks"`
}

// IngestClient posts batches to the ingest endpoint and verifies durable-seq
// acks. It is constructed by the sync agent; it is NEVER on the hook path.
type IngestClient struct {
	// Endpoint is the base URL (scheme MUST be https). IngestPath is appended.
	Endpoint string
	// Token is the SPEC-0127 device bearer token (R-5.2). Sent as
	// Authorization: Bearer <token>. Empty is allowed only for a contract
	// double that does not enforce auth.
	Token string
	// LogID binds the durable-seq signature (the ack is over this log_id).
	LogID string
	// PubKey is the ingest public key the durable-seq signature verifies
	// against (pinned in trust roots / endpoint config). Zero-length disables
	// ack verification → nothing is ever marked synced (fail-closed).
	PubKey ed25519.PublicKey
	// Client is the HTTP client. The CALLER owns TLS policy (InsecureSkipVerify
	// only for loopback). Nil → a 15s-timeout default (verifies certs).
	Client *http.Client
	// ClientEpoch is stamped into each batch body (R-5.3 wire field).
	ClientEpoch int64
}

// eventsURL returns Endpoint + IngestPath after validating the scheme is https.
func (c *IngestClient) eventsURL() (string, error) {
	raw := strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	if raw == "" {
		return "", fmt.Errorf("outbox: ingest endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("outbox: parse ingest endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("outbox: ingest endpoint must be https, got %q", u.Scheme)
	}
	return raw + IngestPath, nil
}

// PostBatch marshals the records into an IngestBatch and POSTs it. records are
// the raw payload_json bytes of each row (already the signed record). It returns
// the parsed response (nil on a non-2xx or transport error), the HTTP status
// (0 on a transport error), and an error.
//
// The caller interprets status: 2xx → inspect acks (valid durable-seq → synced,
// otherwise not); 4xx → auth/validation reject (exit ingest_rejected); 5xx or
// status==0 → transient, backoff.
func (c *IngestClient) PostBatch(ctx context.Context, records [][]byte) (*IngestResponse, int, error) {
	target, err := c.eventsURL()
	if err != nil {
		return nil, 0, err
	}
	raws := make([]json.RawMessage, 0, len(records))
	for _, r := range records {
		raws = append(raws, json.RawMessage(r))
	}
	body, err := json.Marshal(IngestBatch{Records: raws, ClientEpoch: c.ClientEpoch})
	if err != nil {
		return nil, 0, fmt.Errorf("outbox: marshal ingest batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("outbox: build ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "m3c-skillctl-sync/1.0")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("outbox: post ingest batch: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode/100 != 2 {
		return nil, resp.StatusCode, nil
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("outbox: read ingest response: %w", err)
	}
	var out IngestResponse
	if len(bytes.TrimSpace(respBody)) > 0 {
		if err := json.Unmarshal(respBody, &out); err != nil {
			// A 2xx with an unparseable body is a bare-2xx: no usable acks.
			return &IngestResponse{}, resp.StatusCode, nil
		}
	}
	return &out, resp.StatusCode, nil
}

// VerifyAck reports whether ack carries a valid signed durable-seq for this
// client's pinned ingest pubkey and log id. A false result means the caller MUST
// NOT mark the row synced (R-5.3 / AC-4). Fail-closed on a missing pubkey.
func (c *IngestClient) VerifyAck(ack DurableAck) bool {
	if len(c.PubKey) != ed25519.PublicKeySize {
		return false
	}
	if strings.TrimSpace(ack.EventID) == "" || strings.TrimSpace(ack.SeqSigB64) == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(ack.SeqSigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := CanonicalDurableSeq(c.LogID, ack.EventID, ack.DurableSeq)
	return ed25519.Verify(c.PubKey, msg, sig)
}
