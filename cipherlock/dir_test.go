package cipherlock

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDirDecryptDir(t *testing.T) {
	password := []byte("dir-test-password")

	dir := t.TempDir()

	srcDir := filepath.Join(dir, "mydata")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("file a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("file b"), 0644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(srcDir, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "c.txt"), []byte("file c"), 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := filepath.Join(dir, "mydata.cipherlock")
	if err := EncryptDir(srcDir, encryptedFile, password, nil); err != nil {
		t.Fatalf("EncryptDir: %v", err)
	}

	if _, err := os.Stat(encryptedFile); err != nil {
		t.Fatalf("encrypted dir not created: %v", err)
	}

	outDir := filepath.Join(dir, "restored")
	if err := DecryptDir(encryptedFile, outDir, password); err != nil {
		t.Fatalf("DecryptDir: %v", err)
	}

	checkFile := func(path, expected string) {
		data, err := os.ReadFile(filepath.Join(outDir, path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if string(data) != expected {
			t.Fatalf("%s: got %q, want %q", path, string(data), expected)
		}
	}

	checkFile("a.txt", "file a")
	checkFile("b.txt", "file b")
	checkFile("sub/c.txt", "file c")
}

func TestEncryptDirDefaultPath(t *testing.T) {
	password := []byte("default-path")

	dir := t.TempDir()
	srcDir := filepath.Join(dir, "docs")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "readme.txt"), []byte("readme"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := EncryptDir(srcDir, "", password, nil); err != nil {
		t.Fatalf("EncryptDir: %v", err)
	}

	expected := srcDir + ".cipherlock"
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("default output not created: %v", err)
	}
}

// makeMaliciousTarCipherlock builds an encrypted cipherlock archive that, when
// decrypted, expands into a tar.gz whose first entry is header.Name. This is
// used to test that DecryptDir refuses tar-slip paths.
func makeMaliciousTarCipherlock(t *testing.T, password []byte, entryName string) string {
	t.Helper()

	var tarBuf bytes.Buffer
	gw := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name:     entryName,
		Mode:     0644,
		Size:     int64(len("pwned")),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("pwned")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	encryptedFile := filepath.Join(t.TempDir(), "malicious.cipherlock")
	f, err := os.Create(encryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := Encrypt(f, bytes.NewReader(tarBuf.Bytes()), password, nil); err != nil {
		t.Fatal(err)
	}
	return encryptedFile
}

func TestDecryptDirRejectsTarSlip(t *testing.T) {
	password := []byte("slip-test")
	dir := t.TempDir()
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0755); err != nil {
		t.Fatal(err)
	}

	// Plant a sentinel file outside dest; if tar slip works, it will be overwritten.
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"../../sentinel.txt",
		"../sentinel.txt",
		"/tmp/cipherlock-sentinel-abs",
		"sub/../../../sentinel.txt",
	}
	for _, name := range cases {
		enc := makeMaliciousTarCipherlock(t, password, name)
		err := DecryptDir(enc, dest, password)
		if err == nil {
			t.Errorf("entry %q: expected error, got nil", name)
			continue
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Errorf("entry %q: expected refusal, got %v", name, err)
		}
	}

	// The sentinel must still hold its original content.
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "untouched" {
		t.Fatalf("sentinel was modified: %q", string(data))
	}
}
