package cipherlock

import (
	"os"
	"path/filepath"
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
