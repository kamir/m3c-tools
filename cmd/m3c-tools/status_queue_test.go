package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/er1"
)

func TestPrintUploadQueueShowsWaitingUploads(t *testing.T) {
	q := er1.NewQueue(filepath.Join(t.TempDir(), "queue.json"))
	var out bytes.Buffer
	if err := printUploadQueue(&out, q); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Uploads waiting for retry: 0") {
		t.Fatalf("empty queue: %q", out.String())
	}
	if err := q.Add(er1.QueueEntry{ID: "note-1", LastError: "connection refused", RetryCount: 2}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := printUploadQueue(&out, q); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Uploads waiting for retry: 1", "note-1", "attempts=2", "connection refused"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q misses %q", out.String(), want)
		}
	}
}
