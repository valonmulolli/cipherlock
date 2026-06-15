package cipherlock

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptStreamV2Context(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("v0x06 stream context")

	var encrypted bytes.Buffer
	ctx := context.Background()
	err := EncryptStreamV2Context(ctx, &encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptStreamV2Context: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptStreamV2Context(ctx, &decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("DecryptStreamV2Context: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestEncryptStreamV2ContextWithMeta(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("v0x06 with meta")

	cfg := *DefaultConfig
	cfg.FileMeta = &FileMeta{Name: "test.txt", Size: int64(len(plaintext))}

	var encrypted bytes.Buffer
	ctx := context.Background()
	err := EncryptStreamV2Context(ctx, &encrypted, bytes.NewReader(plaintext), password, &cfg)
	if err != nil {
		t.Fatalf("EncryptStreamV2Context: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptStreamV2Context(ctx, &decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("DecryptStreamV2Context: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestEncryptStreamMultiContext(t *testing.T) {
	passwords := [][]byte{[]byte("alice"), []byte("bob")}
	plaintext := []byte("multi-recipient context")

	var encrypted bytes.Buffer
	ctx := context.Background()
	err := EncryptStreamMultiContext(ctx, &encrypted, bytes.NewReader(plaintext), passwords, nil)
	if err != nil {
		t.Fatalf("EncryptStreamMultiContext: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptStreamMultiContext(ctx, &decrypted, &encrypted, passwords[0])
	if err != nil {
		t.Fatalf("DecryptStreamMultiContext: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestDecryptWithMetaContext(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("decrypt-with-meta context")

	cfg := *DefaultConfig
	cfg.FileMeta = &FileMeta{Name: "secret.txt", Size: int64(len(plaintext))}

	var encrypted bytes.Buffer
	err := EncryptStreamV2(&encrypted, bytes.NewReader(plaintext), password, &cfg)
	if err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	var decrypted bytes.Buffer
	ctx := context.Background()
	meta, err := DecryptWithMetaContext(ctx, &decrypted, &encrypted, password)
	if err != nil {
		t.Fatalf("DecryptWithMetaContext: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch")
	}
	if meta == nil || meta.Name != "secret.txt" {
		t.Fatalf("expected meta with name secret.txt, got %+v", meta)
	}
}

func TestDecryptWithMetaContextCancelled(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("cancel decrypt meta")

	var encrypted bytes.Buffer
	err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var decrypted bytes.Buffer
	_, err = DecryptWithMetaContext(ctx, &decrypted, &encrypted, password)
	if err == nil {
		t.Fatal("expected context cancelled error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestReKeyContext(t *testing.T) {
	oldPwd := []byte("old-password")
	newPwd := []byte("new-password")
	plaintext := []byte("rekey context test")

	var encrypted bytes.Buffer
	err := EncryptStream(&encrypted, bytes.NewReader(plaintext), oldPwd, nil)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var rekeyed bytes.Buffer
	ctx := context.Background()
	err = ReKeyContext(ctx, &rekeyed, &encrypted, oldPwd, newPwd, nil)
	if err != nil {
		t.Fatalf("ReKeyContext: %v", err)
	}

	var decrypted bytes.Buffer
	err = Decrypt(&decrypted, &rekeyed, newPwd)
	if err != nil {
		t.Fatalf("Decrypt with new password: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch after rekey")
	}
}

func TestReKeyContextWrongPassword(t *testing.T) {
	oldPwd := []byte("real-password")
	wrongPwd := []byte("wrong-password")
	newPwd := []byte("new-password")
	plaintext := []byte("rekey wrong pwd")

	var encrypted bytes.Buffer
	err := EncryptStream(&encrypted, bytes.NewReader(plaintext), oldPwd, nil)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var rekeyed bytes.Buffer
	ctx := context.Background()
	err = ReKeyContext(ctx, &rekeyed, &encrypted, wrongPwd, newPwd, nil)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestEncryptDecryptDirContext(t *testing.T) {
	password := []byte("test-password")
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(srcFile, []byte("dir context test"), 0644); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "out.cipherlock")
	ctx := context.Background()
	if err := EncryptDirContext(ctx, srcDir, encPath, password, nil); err != nil {
		t.Fatalf("EncryptDirContext: %v", err)
	}

	extractDir := filepath.Join(dir, "extracted")
	if err := DecryptDirContext(ctx, encPath, extractDir, password); err != nil {
		t.Fatalf("DecryptDirContext: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(extractDir, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "dir context test" {
		t.Fatalf("unexpected content: %q", string(data))
	}
}

func TestEncryptDirContextCancelled(t *testing.T) {
	password := []byte("test-password")
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("cancel dir encrypt"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := EncryptDirContext(ctx, srcDir, filepath.Join(dir, "out.cipherlock"), password, nil)
	if err == nil {
		t.Fatal("expected context cancelled error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestDecryptDirContextCancelled(t *testing.T) {
	password := []byte("test-password")
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("cancel dir decrypt"), 0644); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "out.cipherlock")
	if err := EncryptDir(srcDir, encPath, password, nil); err != nil {
		t.Fatalf("EncryptDir: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := DecryptDirContext(ctx, encPath, filepath.Join(dir, "extracted"), password)
	if err == nil {
		t.Fatal("expected context cancelled error, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}
