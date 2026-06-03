package cipherlock

import (
	"bytes"
	"strings"
	"testing"
)

func TestChunkSizeBoundsOnEncrypt(t *testing.T) {
	makeCfg := func(cs int) *Config {
		cfg := *DefaultConfig
		cfg.ChunkSize = cs
		return &cfg
	}

	t.Run("v0x05 too large", func(t *testing.T) {
		var buf bytes.Buffer
		err := EncryptStream(&buf, bytes.NewReader([]byte("x")), []byte("p"), makeCfg(maxChunkSize+1))
		if err == nil {
			t.Fatal("expected error for ChunkSize > maxChunkSize")
		}
		if !strings.Contains(err.Error(), "exceeds maxChunkSize") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("v0x06 too large", func(t *testing.T) {
		var buf bytes.Buffer
		err := EncryptStreamV2(&buf, bytes.NewReader([]byte("x")), []byte("p"), makeCfg(maxChunkSize+1))
		if err == nil {
			t.Fatal("expected error for ChunkSize > maxChunkSize")
		}
	})

	t.Run("v0x07 too large", func(t *testing.T) {
		var buf bytes.Buffer
		err := EncryptStreamMulti(&buf, bytes.NewReader([]byte("x")), [][]byte{[]byte("p")}, makeCfg(maxChunkSize+1))
		if err == nil {
			t.Fatal("expected error for ChunkSize > maxChunkSize")
		}
	})

	t.Run("v0x05 at boundary succeeds", func(t *testing.T) {
		var buf bytes.Buffer
		if err := EncryptStream(&buf, bytes.NewReader([]byte("x")), []byte("p"), makeCfg(maxChunkSize)); err != nil {
			t.Errorf("maxChunkSize should be accepted: %v", err)
		}
		var dec bytes.Buffer
		if err := Decrypt(&dec, bytes.NewReader(buf.Bytes()), []byte("p")); err != nil {
			t.Errorf("decrypt failed: %v", err)
		}
	})
}
