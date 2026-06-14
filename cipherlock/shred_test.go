package cipherlock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShred(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(path, []byte("sensitive data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Shred(path); err != nil {
		t.Fatalf("Shred: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should not exist after shred")
	}
}

func TestShredEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	if err := Shred(path); err != nil {
		t.Fatalf("Shred: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should not exist after shred")
	}
}

func TestShredNonexistent(t *testing.T) {
	err := Shred("/nonexistent/path/file.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestShredOverwritesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := []byte("sensitive secret data")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	fd, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()

	if err := Shred(path); err != nil {
		t.Fatalf("Shred: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should not exist after shred")
	}

	buf := make([]byte, len(content))
	if _, err := fd.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not zero after shred: got %d", i, b)
		}
	}
}
