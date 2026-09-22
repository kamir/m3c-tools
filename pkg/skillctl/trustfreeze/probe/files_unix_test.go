//go:build !windows

package probe

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestRootedFileReaderRefusesFIFO: a FIFO inside an allowed root is refused
// at once with ErrNotRegularFile. A plain open would block until a writer
// appeared, and the reader has no context to give up with (TF02-AC6).
func TestRootedFileReaderRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "os-release")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo not available here: %v", err)
	}
	r := NewRootedFileReader([]string{dir}, 0)
	done := make(chan error, 1)
	go func() {
		_, err := r.ReadFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("ReadFile(FIFO) = %v, want ErrNotRegularFile", err)
		}
	case <-time.After(5 * time.Second):
		// Release the blocked open so the goroutine ends, then fail.
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("ReadFile blocked on a FIFO")
	}
}

// TestOpenRegularFileRefusesFinalSymlink: the open itself does not follow a
// final symlink, so one swapped in after EvalSymlinks cannot redirect it.
func TestOpenRegularFileRefusesFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not available here: %v", err)
	}
	if f, err := openRegularFile(link); err == nil {
		f.Close()
		t.Fatal("openRegularFile followed a final symlink")
	}
	f, err := openRegularFile(target)
	if err != nil {
		t.Fatalf("regular file: %v", err)
	}
	f.Close()
}
