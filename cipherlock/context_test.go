package cipherlock

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestEncryptDecryptContext(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("context-aware round trip")

	var encrypted bytes.Buffer
	ctx := context.Background()
	err := EncryptContext(ctx, &encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptContext: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptContext(ctx, &decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("DecryptContext: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestEncryptContextCancelled(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("this should be cancelled")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var encrypted bytes.Buffer
	err := EncryptContext(ctx, &encrypted, bytes.NewReader(plaintext), password, nil)
	if err == nil {
		t.Fatal("expected context cancelled error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestDecryptContextCancelled(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("decrypt should be cancelled")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var decrypted bytes.Buffer
	err = DecryptContext(ctx, &decrypted, &encrypted, password)
	if err == nil {
		t.Fatal("expected context cancelled error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestEncryptStreamContext(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("stream context")

	var encrypted bytes.Buffer
	ctx := context.Background()
	err := EncryptStreamContext(ctx, &encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptStreamContext: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptStreamContext(ctx, &decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("DecryptStreamContext: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestEncryptMultiContext(t *testing.T) {
	passwords := [][]byte{[]byte("alice"), []byte("bob")}
	plaintext := []byte("multi context test")

	var encrypted bytes.Buffer
	ctx := context.Background()
	err := EncryptMultiContext(ctx, &encrypted, bytes.NewReader(plaintext), passwords, nil)
	if err != nil {
		t.Fatalf("EncryptMultiContext: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptContext(ctx, &decrypted, &encrypted, passwords[0])
	if err != nil {
		t.Fatalf("DecryptContext: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestContextTimeout(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("timeout test")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var encrypted bytes.Buffer
	err := EncryptContext(ctx, &encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptContext: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptContext(ctx, &decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("DecryptContext: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch")
	}
}
