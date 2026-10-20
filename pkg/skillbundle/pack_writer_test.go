package skillbundle

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type failingBundleWriter struct{ err error }

func (writer failingBundleWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestPackToWriterMatchesFileAndPropagatesWriteFailures(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	source := writeFixtureSkill(t)
	opts := PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}
	output := filepath.Join(t.TempDir(), "bundle.skb")
	digest, err := Pack(source, output, opts)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writerDigest, err := PackToWriter(source, &archive, opts)
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if digest != writerDigest || !bytes.Equal(fileBytes, archive.Bytes()) {
		t.Fatal("writer and file pack outputs differ")
	}
	failure := errors.New("synthetic write failure")
	if _, err := PackToWriter(source, failingBundleWriter{failure}, opts); !errors.Is(err, failure) {
		t.Fatalf("write failure not propagated: %v", err)
	}
	if _, err := PackToWriter(source, failingBundleWriter{}, opts); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write not rejected: %v", err)
	}
}
