package skillbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func boundedInflated(t *testing.T, archive []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return raw
}
func boundedGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func boundedPAXArchive(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	header := &tar.Header{Name: "SKILL.md", Size: 1, Mode: 0600, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": strings.Repeat("p", 4096)}}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return boundedGzip(t, raw.Bytes())
}

func TestUnpackInflatedBudget(t *testing.T) {
	archive := makeArchive(t, []titem{dir("assets/"), reg("SKILL.md", "x")})
	raw := boundedInflated(t, archive)
	exact := int64(len(raw))
	t.Run("exact-stream-and-payload-padding", func(t *testing.T) {
		entries, usage, err := UnpackBounded(context.Background(), archive, UnpackOptions{}, exact)
		if err != nil || len(entries) != 2 || usage.Entries != 2 || usage.InflatedBytes != exact {
			t.Fatalf("complete stream rejected/miscounted: entries=%d usage=%+v err=%v", len(entries), usage, err)
		}
		if relset(entries)["SKILL.md"].Content[0] != 'x' {
			t.Fatal("wrong returned body")
		}
	})
	t.Run("cap-minus-one-is-not-EOF", func(t *testing.T) {
		entries, usage, err := UnpackBounded(context.Background(), archive, UnpackOptions{}, exact-1)
		if !errors.Is(err, ErrInflatedLimit) || len(entries) != 0 || usage.InflatedBytes > exact || usage.InflatedBytes <= exact-1 {
			t.Fatalf("stream cap hidden as success/EOF: usage=%+v err=%v", usage, err)
		}
	})
	t.Run("trailing-inflated-byte-after-tar-EOF", func(t *testing.T) {
		extra := boundedGzip(t, append(append([]byte{}, raw...), 0))
		if entries, usage, err := UnpackBounded(context.Background(), extra, UnpackOptions{}, exact); !errors.Is(err, ErrInflatedLimit) || len(entries) != 0 || usage.InflatedBytes != exact+1 {
			t.Fatalf("trailer escaped budget: %+v %v", usage, err)
		}
		if _, usage, err := UnpackBounded(context.Background(), extra, UnpackOptions{}, exact+1); err != nil || usage.InflatedBytes != exact+1 {
			t.Fatalf("exact expanded trailer boundary: %+v %v", usage, err)
		}
	})
	t.Run("hidden-PAX-before-first-visible-header", func(t *testing.T) {
		pax := boundedPAXArchive(t)
		if entries, usage, err := UnpackBounded(context.Background(), pax, UnpackOptions{}, 1024); !errors.Is(err, ErrInflatedLimit) || len(entries) != 0 || usage.Entries != 0 || usage.InflatedBytes > 1025 {
			t.Fatalf("PAX bypassed pre-header cap: %+v %v", usage, err)
		}
		full := int64(len(boundedInflated(t, pax)))
		if entries, usage, err := UnpackBounded(context.Background(), pax, UnpackOptions{}, full); err != nil || len(entries) != 1 || usage.Entries != 1 || usage.InflatedBytes != full {
			t.Fatalf("PAX exact full stream: %+v %v", usage, err)
		}
	})
	t.Run("invalid-or-overflow-cap", func(t *testing.T) {
		for _, cap := range []int64{0, -1, math.MaxInt64} {
			if entries, _, err := UnpackBounded(context.Background(), archive, UnpackOptions{}, cap); !errors.Is(err, ErrInflatedLimit) || len(entries) != 0 {
				t.Fatalf("invalid cap %d accepted: %v", cap, err)
			}
		}
	})
	t.Run("canceled-context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if entries, _, err := UnpackBounded(ctx, archive, UnpackOptions{}, exact); !errors.Is(err, context.Canceled) || len(entries) != 0 {
			t.Fatalf("cancellation lost: %v", err)
		}
	})
	t.Run("gzip-integrity-and-truncation", func(t *testing.T) {
		corrupt := append([]byte{}, archive...)
		corrupt[len(corrupt)-8] ^= 1
		for _, blob := range [][]byte{corrupt, archive[:len(archive)-4]} {
			if entries, _, err := UnpackBounded(context.Background(), blob, UnpackOptions{}, exact+1024); err == nil || len(entries) != 0 || errors.Is(err, io.EOF) {
				t.Fatalf("corrupt/truncated stream accepted: %v", err)
			}
		}
	})
	t.Run("legacy-default-and-derived-cap-overflow", func(t *testing.T) {
		entries, err := Unpack(archive, UnpackOptions{})
		if err != nil || len(entries) != 2 {
			t.Fatalf("legacy default changed: %v", err)
		}
		if _, err := Unpack(archive, UnpackOptions{MaxBytes: math.MaxInt64, MaxFiles: math.MaxInt}); !errors.Is(err, ErrInflatedLimit) {
			t.Fatalf("derived cap overflow accepted: %v", err)
		}
	})
}
