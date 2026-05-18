package cipherlock

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReKey(t *testing.T) {
	oldPwd := []byte("old-password")
	newPwd := []byte("new-password")
	plaintext := []byte("rekey test data")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), oldPwd, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var rekeyed bytes.Buffer
	err = ReKey(&rekeyed, &encrypted, oldPwd, newPwd, nil)
	if err != nil {
		t.Fatalf("ReKey: %v", err)
	}

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, &rekeyed, newPwd)
	if err != nil {
		t.Fatalf("Decrypt with new password: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("re-key round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestReKeyWrongOldPassword(t *testing.T) {
	oldPwd := []byte("old-password")
	wrongPwd := []byte("wrong-password")
	newPwd := []byte("new-password")

	var encrypted bytes.Buffer
	Encrypt(&encrypted, bytes.NewReader([]byte("data")), oldPwd, nil)

	err := ReKey(&bytes.Buffer{}, &encrypted, wrongPwd, newPwd, nil)
	if err == nil {
		t.Fatal("expected error for wrong old password, got nil")
	}
}

func TestReKeyFile(t *testing.T) {
	oldPwd := []byte("old-password")
	newPwd := []byte("new-password")
	plaintext := []byte("file rekey test")

	dir := t.TempDir()
	src := filepath.Join(dir, "secret.enc")

	var buf bytes.Buffer
	Encrypt(&buf, bytes.NewReader(plaintext), oldPwd, nil)
	if err := os.WriteFile(src, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "secret.rekeyed")
	if err := ReKeyFile(src, dest, oldPwd, newPwd, nil); err != nil {
		t.Fatalf("ReKeyFile: %v", err)
	}

	var result bytes.Buffer
	if err := Decrypt(&result, bytes.NewReader(mustReadFile(t, dest)), newPwd); err != nil {
		t.Fatalf("Decrypt after rekey: %v", err)
	}

	if !bytes.Equal(plaintext, result.Bytes()) {
		t.Fatal("re-key file round-trip mismatch")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
