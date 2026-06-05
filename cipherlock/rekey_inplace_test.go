package cipherlock

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writePlaintext(t *testing.T, name string, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReKeyFileInPlacePreservesOnFailure(t *testing.T) {
	plaintext := []byte("rekey in place test data, long enough to be interesting")
	srcPath := writePlaintext(t, "blob.txt", plaintext)

	encPath := srcPath + ".encrypted"
	if err := EncryptFile(srcPath, encPath, []byte("old"), DefaultConfig); err != nil {
		t.Fatal(err)
	}
	originalBytes, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong old password: ReKeyFile should fail AND leave the
	// original ciphertext on disk (not truncate to 0 bytes).
	if err := ReKeyFile(encPath, "", []byte("wrong-old"), []byte("new"), DefaultConfig); err == nil {
		t.Fatal("expected error for wrong old password")
	}
	afterBytes, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, afterBytes) {
		t.Errorf("source file was modified on failed rekey")
	}

	// Tempfiles created during the failed attempt should have been cleaned up.
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(encPath), ".cipherlock-rekey-*"))
	if len(matches) > 0 {
		t.Errorf("leftover tempfile(s) after failed rekey: %v", matches)
	}
}

func TestReKeyFileInPlaceSuccess(t *testing.T) {
	plaintext := []byte("in-place rekey happy path")
	srcPath := writePlaintext(t, "blob.txt", plaintext)
	encPath := srcPath + ".encrypted"
	if err := EncryptFile(srcPath, encPath, []byte("old"), DefaultConfig); err != nil {
		t.Fatal(err)
	}

	if err := ReKeyFile(encPath, "", []byte("old"), []byte("new"), DefaultConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(encPath); err != nil {
		t.Fatalf("source file missing after in-place rekey: %v", err)
	}

	// Old password should no longer decrypt; new password should.
	decPath := encPath[:len(encPath)-len(".encrypted")]
	if err := DecryptFile(encPath, decPath, []byte("old")); err == nil {
		t.Error("old password still decrypts after in-place rekey")
	}
	if err := DecryptFile(encPath, decPath, []byte("new")); err != nil {
		t.Fatalf("new password should decrypt after rekey: %v", err)
	}
	body, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, plaintext) {
		t.Errorf("plaintext mismatch: got %q want %q", body, plaintext)
	}
}
