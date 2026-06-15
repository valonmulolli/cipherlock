package cipherlock

import (
	"bytes"
	"testing"
	"time"
)

// TestEncryptStreamWithFileMetaUpgradesToV06 verifies that EncryptStream
// auto-upgrades to v0x06 (encrypted metadata) when FileMeta is set, instead
// of returning ErrV05MetaUnsupported.
func TestEncryptStreamWithFileMetaUpgradesToV06(t *testing.T) {
	meta := &FileMeta{Name: "secret.txt", Size: 1, ModTime: time.Unix(1700000000, 0)}
	cfg := *DefaultConfig
	cfg.FileMeta = meta

	var encrypted bytes.Buffer
	if err := EncryptStream(&encrypted, bytes.NewReader([]byte("x")), []byte("p"), &cfg); err != nil {
		t.Fatalf("EncryptStream with FileMeta should auto-upgrade, got: %v", err)
	}

	var decrypted bytes.Buffer
	gotMeta, err := DecryptWithMeta(&decrypted, &encrypted, []byte("p"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if gotMeta == nil {
		t.Fatal("expected FileMeta on decrypt")
	}
	if gotMeta.Name != "secret.txt" {
		t.Errorf("expected name secret.txt, got %q", gotMeta.Name)
	}
	if decrypted.String() != "x" {
		t.Errorf("expected 'x', got %q", decrypted.Bytes())
	}
}
