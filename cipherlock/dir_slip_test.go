package cipherlock

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestTarSymlinkExtracted(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "subdir/",
	}); err != nil {
		t.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "mylink",
		Linkname: "subdir",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	if err := untarGzDir(dest, &buf); err != nil {
		t.Fatalf("symlink extraction failed: %v", err)
	}

	linkPath := filepath.Join(dest, "mylink")
	linkTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if linkTarget != "subdir" {
		t.Fatalf("got link target %q, want %q", linkTarget, "subdir")
	}
}

func TestTarSymlinkAbsoluteOutsideRejected(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "outlink",
		Linkname: "/etc/passwd",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	err := untarGzDir(dest, &buf)
	if err == nil {
		t.Fatal("expected error for absolute symlink outside dest, got nil")
	}
}

func TestTarSymlinkDotDotOutsideRejected(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "outlink",
		Linkname: "../../etc/passwd",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	err := untarGzDir(dest, &buf)
	if err == nil {
		t.Fatal("expected error for ../ symlink outside dest, got nil")
	}
}

func TestTarSymlinkInsideAllowed(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "inner",
		Linkname: ".",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	if err := untarGzDir(dest, &buf); err != nil {
		t.Fatalf("inner symlink should be allowed: %v", err)
	}

	linkPath := filepath.Join(dest, "inner")
	linkTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if linkTarget != "." {
		t.Fatalf("got link target %q, want %q", linkTarget, ".")
	}
}

func TestTarHardLinkRejectedOutside(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "extract")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "safe.txt",
		Size:     4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeLink,
		Name:     "escape",
		Linkname: "../../tmp/outside",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()

	err := untarGzDir(dest, &buf)
	if err == nil {
		t.Fatal("expected error for hard link outside dest, got nil")
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
