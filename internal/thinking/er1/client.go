// Package er1 is the Thinking Engine's ER1 REST client.
//
// SPEC-0167 §Isolation Model requires the client be bound to EXACTLY
// ONE user_context_id at construction and refuse any other at
// runtime. This is a hard check, not a review-gate assumption.
//
// Week 1: we ship a stub that returns canned responses without
// touching the network. The ctx-guard behavior is real and tested.
package er1

import (
	"errors"
	"fmt"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// Item is the minimal ER1 representation used by the engine. The
// real client will fill this from the ER1 REST API.
type Item struct {
	DocID     string
	CtxID     string
	Tags      []string
	Summary   string
	CreatedAt time.Time
}

// Client reads and writes against one ER1 context.
type Client interface {
	// GetItem fetches a single ER1 item. Rejects any ctxID other
	// than the one passed to the constructor.
	GetItem(ctxID string, docID string) (Item, error)

	// CreateArtifact persists an Artifact to ER1 (D2: artifacts.created
	// topic is truth, this is the projection). Rejects any ctxID
	// other than the constructor's.
	CreateArtifact(ctxID string, a schema.Artifact) (string, error)
}

// stubClient is the Week 1 in-memory client.
type stubClient struct {
	owner   mctx.Raw
	ownerID string // cached ownerRaw.Value() for equality checks
}

// New returns an ER1 client bound to exactly one user context. The
// raw value is used verbatim when comparing subsequent calls; the
// hash is never used for equality because the caller's call-site
// identifier is also a raw id.
func New(owner mctx.Raw) Client {
	return &stubClient{owner: owner, ownerID: owner.Value()}
}

func (c *stubClient) checkCtx(called string) error {
	if called == "" {
		return errors.New("er1: empty ctxID")
	}
	if called != c.ownerID {
		return fmt.Errorf(
			"er1: ctx mismatch — client bound to %s, call used %s",
			redact(c.ownerID), redact(called),
		)
	}
	return nil
}

func (c *stubClient) GetItem(ctxID, docID string) (Item, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return Item{}, err
	}
	// Week 1 stub: return a canned observation-style item.
	return Item{
		DocID:     docID,
		CtxID:     ctxID,
		Tags:      []string{"stub"},
		Summary:   "[stub] ER1 item " + docID,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (c *stubClient) CreateArtifact(ctxID string, a schema.Artifact) (string, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return "", err
	}
	// Week 1 stub: pretend we wrote, return a synthetic er1 ref.
	ref := fmt.Sprintf("er1://%s/artifacts/%s", redact(ctxID), a.ArtifactID)
	return ref, nil
}

// redact returns a short-hash-style identifier so logs never carry
// the raw user id. Parallels internal/thinking/ctx.Raw.String().
func redact(s string) string {
	if len(s) <= 4 {
		return "<ctx>"
	}
	return s[:2] + "…" + s[len(s)-2:]
}
