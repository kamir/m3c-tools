package e2e

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

func TestThumbnailFetch(t *testing.T) {
	SkipIfNoYTCalls(t)
	fetcher, _ := transcript.NewFetcher(nil)
	data, err := fetcher.FetchThumbnail(testVideoID)
	if err != nil {
		t.Fatalf("FetchThumbnail() error: %v", err)
	}
	if len(data) < 1000 {
		t.Errorf("Thumbnail too small: %d bytes", len(data))
	}
	// Check JPEG magic bytes
	if data[0] != 0xFF || data[1] != 0xD8 {
		t.Error("Thumbnail is not a valid JPEG")
	}
	t.Logf("Thumbnail: %d bytes (%.1f KB)", len(data), float64(len(data))/1024)
}

func TestThumbnailNMSHcSq8nMs(t *testing.T) {
	SkipIfNoYTCalls(t)
	fetcher, _ := transcript.NewFetcher(nil)
	data, err := fetcher.FetchThumbnail("NMSHcSq8nMs")
	if err != nil {
		t.Fatalf("FetchThumbnail() error: %v", err)
	}
	if len(data) < 10000 {
		t.Errorf("Expected large thumbnail, got %d bytes", len(data))
	}
	t.Logf("NMSHcSq8nMs thumbnail: %d bytes", len(data))
}

func TestThumbnailURL(t *testing.T) {
	url := transcript.ThumbnailURL(testVideoID, transcript.ThumbnailMaxRes)
	expected := "https://img.youtube.com/vi/dQw4w9WgXcQ/maxresdefault.jpg"
	if url != expected {
		t.Errorf("Expected %s, got %s", expected, url)
	}
}
