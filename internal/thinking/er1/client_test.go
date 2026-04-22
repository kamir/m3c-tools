package er1

import (
	"testing"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

func TestGetItemAcceptsOwnCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c := New(raw)
	it, err := c.GetItem("user-A", "doc-1")
	if err != nil {
		t.Fatal(err)
	}
	if it.DocID != "doc-1" || it.CtxID != "user-A" {
		t.Errorf("bad item: %+v", it)
	}
}

func TestGetItemRejectsForeignCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c := New(raw)
	if _, err := c.GetItem("user-B", "doc-1"); err == nil {
		t.Errorf("expected ctx mismatch error")
	}
}

func TestCreateArtifactRejectsForeignCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c := New(raw)
	art := schema.Artifact{ArtifactID: "a-1", SchemaVer: schema.CurrentSchemaVer}
	if _, err := c.CreateArtifact("user-B", art); err == nil {
		t.Errorf("expected ctx mismatch error")
	}
}

func TestCreateArtifactReturnsRef(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c := New(raw)
	art := schema.Artifact{ArtifactID: "a-1", SchemaVer: schema.CurrentSchemaVer}
	ref, err := c.CreateArtifact("user-A", art)
	if err != nil {
		t.Fatal(err)
	}
	if ref == "" {
		t.Errorf("empty ref")
	}
}

func TestEmptyCtxRejected(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c := New(raw)
	if _, err := c.GetItem("", "doc-1"); err == nil {
		t.Errorf("expected error on empty ctx")
	}
}
