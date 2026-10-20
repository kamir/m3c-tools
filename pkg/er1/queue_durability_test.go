package er1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestEnqueueFailurePersistsCompletePayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	payload := &UploadPayload{TranscriptData: []byte("original text"), TranscriptFilename: "missing.txt", AudioData: []byte("original audio"), AudioFilename: "missing.wav", ImageData: []byte("original image"), ImageFilename: "missing.jpg", Tags: "capture", ContentType: "custom", DocID: "document", DoTranscribe: true, CurrentTime: "2026-10-20 12:00:00"}
	want := *payload
	cfg := &Config{APIURL: "https://example.test/upload_2", ContextID: "original-context", ContentType: "default", APIKey: "secret-not-for-disk"}
	entry := EnqueueFailure(path, "capture", payload, payload.Tags, errors.New("offline"), cfg)
	if entry == nil {
		t.Fatal("enqueue failed")
	}
	payload.AudioData[0] = '!'
	entries, err := NewQueue(path).ReadEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v, error=%v", entries, err)
	}
	got, err := PayloadFromQueueEntry(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	want.AudioData = []byte("original audio")
	if !reflect.DeepEqual(got, &want) {
		t.Fatalf("restored payload=%+v, want=%+v", got, want)
	}
	metadata, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(metadata, []byte("secret-not-for-disk")) || bytes.Contains(metadata, []byte("TranscriptData")) {
		t.Fatalf("queue metadata includes credentials or inline payload: %s", metadata)
	}
	if !filepath.IsAbs(entry.PayloadPath) {
		t.Fatal("payload path must be absolute")
	}
	info, err := os.Stat(entry.PayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("payload mode %o", info.Mode().Perm())
	}
	if err := os.WriteFile(entry.PayloadPath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PayloadFromQueueEntry(*entry); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestQueueCorruptionIsPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	original := []byte("[{broken")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	q := NewQueue(path)
	if _, err := q.ReadEntries(); err == nil {
		t.Fatal("corruption silently accepted")
	}
	if q.Err() == nil {
		t.Fatal("read error not exposed")
	}
	for _, mutate := range []func() error{func() error { return q.Add(QueueEntry{ID: "new"}) }, func() error { return q.Remove("old") }, func() error { return q.UpdateRetry("old", errors.New("failed")) }, q.Clear} {
		if err := mutate(); err == nil {
			t.Fatal("mutation accepted corrupt queue")
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("corrupt queue replaced: %q, %v", got, err)
	}
}

func TestQueueConcurrentHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			q := NewQueue(path)
			for i := 0; i < 15; i++ {
				if err := q.Add(QueueEntry{ID: fmt.Sprintf("%d-%d", worker, i)}); err != nil {
					t.Error(err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	entries, err := NewQueue(path).ReadEntries()
	if err != nil || len(entries) != 120 {
		t.Fatalf("entries=%d error=%v", len(entries), err)
	}
}

func TestQueueProcessWriter(t *testing.T) {
	path := os.Getenv("M3C_TEST_QUEUE_PATH")
	if path == "" {
		return
	}
	for i := 0; i < 10; i++ {
		if err := NewQueue(path).Add(QueueEntry{ID: fmt.Sprintf("%s-%d", os.Getenv("M3C_TEST_QUEUE_WORKER"), i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueueConcurrentProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestQueueProcessWriter$")
			cmd.Env = append(os.Environ(), "M3C_TEST_QUEUE_PATH="+path, fmt.Sprintf("M3C_TEST_QUEUE_WORKER=%d", i))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("worker: %v %s", err, output)
			}
		}(i)
	}
	wg.Wait()
	entries, err := NewQueue(path).ReadEntries()
	if err != nil || len(entries) != 40 {
		t.Fatalf("entries=%d error=%v", len(entries), err)
	}
}

func TestRetryRefusesMissingOriginalAndChangedTarget(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	cfg := &Config{APIURL: server.URL, APIKey: "test", ContextID: "new", UploadTimeout: 1}
	for _, entry := range []QueueEntry{
		{ID: "missing", APIURL: server.URL, ContextID: "new", TranscriptPath: filepath.Join(t.TempDir(), "missing.txt")},
		{ID: "legacy-unbound"},
		{ID: "wrong-context", APIURL: server.URL, ContextID: "original"},
		{ID: "wrong-endpoint", APIURL: "https://other.example/upload_2", ContextID: "new"},
	} {
		if _, err := RetryUpload(cfg, entry); err == nil {
			t.Fatalf("entry %s accepted", entry.ID)
		}
	}
	if requests != 0 {
		t.Fatalf("sent %d incomplete or misdirected uploads", requests)
	}
}

func TestRetryOwnersDoNotUploadSameSnapshotConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	q := NewQueue(path)
	if err := q.Add(QueueEntry{ID: "one"}); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	first := NewRetryRunner(q, func(QueueEntry) error { close(entered); <-release; return nil }, 3)
	go func() { defer close(done); first.ProcessOnce(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("retry did not start")
	}
	second := NewRetryRunner(NewQueue(path), func(QueueEntry) error { t.Error("concurrent duplicate upload"); return nil }, 3)
	second.ProcessOnce(context.Background())
	close(release)
	<-done
	if q.Len() != 0 {
		t.Fatal("successful retry not removed")
	}
}

func TestQueueLegacyFormatRemainsReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	data, err := json.Marshal([]QueueEntry{{ID: "legacy"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := NewQueue(path).ReadEntries()
	if err != nil || len(entries) != 1 || entries[0].ID != "legacy" {
		t.Fatalf("legacy entries=%v error=%v", entries, err)
	}
}

func TestUploadDurableCommitsBeforeRequestAndCleansAfterSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	var payloadPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries, err := NewQueue(path).ReadEntries()
		if err != nil || len(entries) != 1 {
			t.Errorf("request began without durable entry: %v %v", entries, err)
			w.WriteHeader(500)
			return
		}
		payloadPath = entries[0].PayloadPath
		payload, err := PayloadFromQueueEntry(entries[0])
		if err != nil || string(payload.TranscriptData) != "original" {
			t.Errorf("payload not durably readable: %v %v", payload, err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"doc_id":"accepted"}`))
	}))
	defer server.Close()
	cfg := &Config{APIURL: server.URL, APIKey: "test", UploadTimeout: 1}
	response, entry, err := UploadDurable(cfg, &UploadPayload{TranscriptData: []byte("original"), TranscriptFilename: "original.txt"}, path, "capture")
	if err != nil || entry != nil || response.DocID != "accepted" {
		t.Fatalf("response=%v entry=%v error=%v", response, entry, err)
	}
	if NewQueue(path).Len() != 0 {
		t.Fatal("delivered entry still pending")
	}
	if _, err := os.Stat(payloadPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delivered snapshot still exists: %v", err)
	}
}

func TestUploadDurableFailureRetainsOriginals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	cfg := &Config{APIURL: server.URL, APIKey: "test", UploadTimeout: 1}
	_, entry, err := UploadDurable(cfg, &UploadPayload{AudioData: []byte("original audio"), AudioFilename: "audio.wav", DoTranscribe: true}, path, "audio")
	if err == nil || entry == nil {
		t.Fatalf("entry=%v error=%v", entry, err)
	}
	entries, err := NewQueue(path).ReadEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v error=%v", entries, err)
	}
	payload, err := PayloadFromQueueEntry(entries[0])
	if err != nil || string(payload.AudioData) != "original audio" || !payload.DoTranscribe {
		t.Fatalf("payload=%v error=%v", payload, err)
	}
	runner := NewRetryRunner(NewQueue(path), func(QueueEntry) error { t.Fatal("exhausted entry retried"); return nil }, 1)
	runner.Backoff = func(int) time.Duration { return 0 }
	runner.ProcessOnce(context.Background())
	if NewQueue(path).Len() != 1 {
		t.Fatal("exhausted original was removed")
	}
}

func TestUploadDurablePersistenceFailureNeverSends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queue.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	defer server.Close()
	_, entry, err := UploadDurable(&Config{APIURL: server.URL, APIKey: "test"}, &UploadPayload{TranscriptData: []byte("original")}, path, "capture")
	if err == nil || entry != nil || requests != 0 {
		t.Fatalf("entry=%v error=%v requests=%d", entry, err, requests)
	}
}

func TestUploadDurableBusyRetryPersistsWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	lock, err := lockQueueFile(path+".retry.lock", false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, entry, err := UploadDurable(&Config{APIURL: "https://example.test/upload_2"}, &UploadPayload{TranscriptData: []byte("original")}, path, "capture")
		if !errors.Is(err, ErrUploadPending) || entry == nil {
			t.Errorf("entry=%v error=%v", entry, err)
			return
		}
		payload, err := PayloadFromQueueEntry(*entry)
		if err != nil || string(payload.TranscriptData) != "original" {
			t.Errorf("payload=%v error=%v", payload, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("capture blocked on active network retry")
	}
}

func TestQueueClearDeletesManagedPayloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	entry := EnqueueFailure(path, "capture", &UploadPayload{TranscriptData: []byte("private")}, "", nil)
	if entry == nil {
		t.Fatal("enqueue failed")
	}
	if err := NewQueue(path).Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry.PayloadPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared snapshot remains: %v", err)
	}
	if NewQueue(path).Len() != 0 {
		t.Fatal("queue not cleared")
	}
}
