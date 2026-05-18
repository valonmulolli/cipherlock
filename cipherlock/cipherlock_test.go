package cipherlock

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("hello, this is a secret message")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestEncryptDecryptLarge(t *testing.T) {
	password := []byte("test-password")
	plaintext := make([]byte, 10*1024*1024)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatal("round-trip mismatch for large data")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")
	plaintext := []byte("sensitive data")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, &encrypted, wrongPassword)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("expected 'decryption failed' error, got: %v", err)
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("sensitive data")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	corrupted := encrypted.Bytes()
	corrupted[len(corrupted)-5] ^= 0xFF

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, bytes.NewReader(corrupted), password)
	if err == nil {
		t.Fatal("expected error for corrupted data, got nil")
	}
}

func TestEmptyData(t *testing.T) {
	password := []byte("test-password")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader([]byte{}), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(decrypted.Bytes()) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(decrypted.Bytes()))
	}
}

func TestStreamEncryptDecrypt(t *testing.T) {
	password := []byte("stream-test")
	plaintext := []byte("streaming test data")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	limited := io.LimitReader(&encrypted, int64(encrypted.Len()))

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, limited, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestInvalidFormat(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte("not a valid cipherlock file"))

	var decrypted bytes.Buffer
	err := Decrypt(&decrypted, &buf, []byte("password"))
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}
}
