package cipherlock

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEncryptStreamRejectsFileMeta(t *testing.T) {
	cfg := *DefaultConfig
	cfg.FileMeta = &FileMeta{Name: "leaky.txt", ModTime: time.Unix(1700000000, 0)}
	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader([]byte("x")), []byte("p"), &cfg)
	if !errors.Is(err, ErrV05MetaUnsupported) {
		t.Fatalf("expected ErrV05MetaUnsupported, got %v", err)
	}
	if !strings.Contains(err.Error(), "EncryptStreamV2") {
		t.Errorf("error should mention the v0x06 path, got %q", err.Error())
	}
}
