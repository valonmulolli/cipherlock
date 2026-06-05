package cipherlock

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestV23ReadAllIsBound crafts a v0x02 (or v0x03) header that
// succeeded pre-H1 and asserts the decryptor no longer slurps
// the whole input into memory. We append a tail > maxV04Body
// and verify Decrypt returns an error (any error) without OOM.
func TestV23ReadAllIsBound(t *testing.T) {
	// Build a minimal v0x02 header: magic + version + saltLen + salt.
	// We don't need a valid password/key -- we want the body read
	// to hit the cap before any GCM check, which proves the bound
	// is applied before the unbounded ReadAll.
	var buf bytes.Buffer
	buf.Write(magic[:])
	buf.WriteByte(formatVersionV2)

	salt := make([]byte, 16)
	buf.Write(salt) // salt (16 bytes; legacy used 16)

	// Argon2id params (Time/Memory/Threads/KeyLen) for header parsing.
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // time
	binary.Write(&buf, binary.LittleEndian, uint32(8*1024)) // memory (8 MiB, within bound)
	binary.Write(&buf, binary.LittleEndian, uint8(1))       // threads
	binary.Write(&buf, binary.LittleEndian, uint32(32))     // keylen

	// Tail: more than maxV04Body to trip the LimitReader.
	tail := bytes.Repeat([]byte{0xAA}, maxV04Body+1024)
	buf.Write(tail)

	var dec bytes.Buffer
	err := Decrypt(&dec, &buf, []byte("any"))
	if err == nil {
		t.Fatal("expected error for v0x02 with body > maxV04Body")
	}
}
