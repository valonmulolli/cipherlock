package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShredSingleFile(t *testing.T) {
	dir := t.TempDir()

	filePath := filepath.Join(dir, "testfile.txt")
	if err := os.WriteFile(filePath, []byte("sensitive data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := shredCmd.RunE(shredCmd, []string{filePath}); err != nil {
		t.Fatalf("shred failed: %v", err)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatal("file was not removed after shred")
	}
}

func TestShredMultipleFiles(t *testing.T) {
	dir := t.TempDir()

	files := []string{"a.txt", "b.txt", "c.txt"}
	var paths []string
	for _, name := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}

	if err := shredCmd.RunE(shredCmd, paths); err != nil {
		t.Fatalf("shred failed: %v", err)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("file %s was not removed after shred", p)
		}
	}
}

func TestShredDirectoryFails(t *testing.T) {
	dir := t.TempDir()

	if err := shredCmd.RunE(shredCmd, []string{dir}); err == nil {
		t.Fatal("expected error for directory shred, got nil")
	}
}
