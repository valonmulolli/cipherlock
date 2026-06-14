package cipherlock

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestTarSymlinkEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	// The current code silently skips TypeSymlink entries. Verify
	// the extraction still succeeds (the symlink is just dropped).
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "outdir",
		Linkname: "../../tmp",
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "outdir/evil.sh",
		Size:     4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	if err := untarGzDir(dest, &buf); err != nil {
		t.Fatalf("symlink entries are dropped, extraction should succeed: %v", err)
	}
}

func TestTarSlipAbsolutePathRejected(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "/etc/cron.d/evil",
		Size:     4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	err := untarGzDir(dest, &buf)
	if err == nil {
		t.Fatal("expected error for absolute path, got nil")
	}
}

func TestTarSlipDotDotRejected(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "../../tmp/evil.sh",
		Size:     4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	err := untarGzDir(dest, &buf)
	if err == nil {
		t.Fatal("expected error for ../ path, got nil")
	}
}

func TestTarSlipSymlinkFollowRejected(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")
	os.MkdirAll(dest, 0755)

	// Create a symlink outside dest that the tar-extraction symlink targets.
	// The unsafe symlink is created by the attacker on disk before restoring.
	outside := filepath.Join(dir, "outside")
	rogueDir := filepath.Join(dest, "linkdir")
	os.Symlink(outside, rogueDir)

	// Now restore a tar that has a regular file at "linkdir/evil.txt".
	// The restored path dest/linkdir/evil.txt resolves through the linkdir
	// symlink to dir/outside/evil.txt -- which is outside dest.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "linkdir/evil.txt",
		Size:     4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	err := untarGzDir(dest, &buf)
	if err == nil {
		t.Fatal("expected error for symlink-follow tar-slip, got nil")
	}
}

func TestNormalTarExtractsSuccessfully(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	// Build a normal tar (no escapes).
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "mydir/",
	}); err != nil {
		t.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "mydir/hello.txt",
		Size:     12,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello world!")); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	if err := untarGzDir(dest, &buf); err != nil {
		t.Fatalf("normal tar should extract without error: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dest, "mydir", "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello world!" {
		t.Fatalf("content mismatch: got %q", body)
	}
}
