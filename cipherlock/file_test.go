package cipherlock

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptFileDecryptFile(t *testing.T) {
	password := []byte("file-test-password")
	plaintext := []byte("file-based encryption test")

	dir := t.TempDir()
	src := filepath.Join(dir, "original.txt")
	if err := os.WriteFile(src, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(src, "", password, nil); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	encrypted := src + ".encrypted"
	if _, err := os.Stat(encrypted); err != nil {
		t.Fatalf("encrypted file not created: %v", err)
	}

	if err := DecryptFile(encrypted, "", password); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	result, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, result) {
		t.Fatalf("round-trip mismatch: got %q, want %q", result, plaintext)
	}
}

func TestEncryptFileCustomDest(t *testing.T) {
	password := []byte("custom-dest")
	plaintext := []byte("custom destination test")

	dir := t.TempDir()
	src := filepath.Join(dir, "source.txt")
	dst := filepath.Join(dir, "custom.enc")
	if err := os.WriteFile(src, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(src, dst, password, nil); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("custom output not created: %v", err)
	}

	result := filepath.Join(dir, "decrypted")
	if err := DecryptFile(dst, result, password); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestIsEncrypted(t *testing.T) {
	password := []byte("detect-test")
	plaintext := []byte("detect me")

	dir := t.TempDir()
	encFile := filepath.Join(dir, "test.encrypted")

	var buf bytes.Buffer
	if err := Encrypt(&buf, bytes.NewReader(plaintext), password, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encFile, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	ok, err := IsEncrypted(encFile)
	if err != nil {
		t.Fatalf("IsEncrypted: %v", err)
	}
	if !ok {
		t.Fatal("expected IsEncrypted to be true")
	}

	plainFile := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plainFile, []byte("not encrypted"), 0644); err != nil {
		t.Fatal(err)
	}

	ok, err = IsEncrypted(plainFile)
	if err != nil {
		t.Fatalf("IsEncrypted: %v", err)
	}
	if ok {
		t.Fatal("expected IsEncrypted to be false for plain file")
	}
}

func TestDecryptFileWrongPassword(t *testing.T) {
	password := []byte("correct")
	wrongPassword := []byte("wrong")

	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(src, "", password, nil); err != nil {
		t.Fatal(err)
	}

	err := DecryptFile(src+".encrypted", "", wrongPassword)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}
