package cipherlock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestEncryptMultiDecrypt(t *testing.T) {
	plaintext := []byte("Hello, multi-recipient world!")
	passwords := [][]byte{[]byte("password1"), []byte("password2"), []byte("password3")}

	var buf bytes.Buffer
	err := EncryptMulti(&buf, bytes.NewReader(plaintext), passwords, nil)
	if err != nil {
		t.Fatalf("EncryptMulti failed: %v", err)
	}

	encrypted := buf.Bytes()

	for _, pwd := range passwords {
		var decBuf bytes.Buffer
		err := Decrypt(&decBuf, bytes.NewReader(encrypted), pwd)
		if err != nil {
			t.Fatalf("Decrypt with password %q failed: %v", string(pwd), err)
		}
		if !bytes.Equal(decBuf.Bytes(), plaintext) {
			t.Fatalf("Decrypt with password %q: got %q, want %q", string(pwd), decBuf.Bytes(), plaintext)
		}
	}
}

func TestEncryptMultiWrongPassword(t *testing.T) {
	plaintext := []byte("secret data")
	passwords := [][]byte{[]byte("pwd1"), []byte("pwd2")}

	var buf bytes.Buffer
	err := EncryptMulti(&buf, bytes.NewReader(plaintext), passwords, nil)
	if err != nil {
		t.Fatalf("EncryptMulti failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = Decrypt(&decBuf, bytes.NewReader(buf.Bytes()), []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestEncryptMultiWithChecksum(t *testing.T) {
	plaintext := []byte("data with checksum")
	passwords := [][]byte{[]byte("p1"), []byte("p2")}
	cfg := &Config{
		SaltLen:  DefaultConfig.SaltLen,
		Time:     DefaultConfig.Time,
		Memory:   DefaultConfig.Memory,
		Threads:  DefaultConfig.Threads,
		KeyLen:   DefaultConfig.KeyLen,
		Checksum: true,
	}

	var buf bytes.Buffer
	err := EncryptMulti(&buf, bytes.NewReader(plaintext), passwords, cfg)
	if err != nil {
		t.Fatalf("EncryptMulti failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = Decrypt(&decBuf, bytes.NewReader(buf.Bytes()), []byte("p1"))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptMultiSinglePassword(t *testing.T) {
	plaintext := []byte("single recipient via multi API")
	passwords := [][]byte{[]byte("onlyone")}

	var buf bytes.Buffer
	err := EncryptMulti(&buf, bytes.NewReader(plaintext), passwords, nil)
	if err != nil {
		t.Fatalf("EncryptMulti failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = Decrypt(&decBuf, bytes.NewReader(buf.Bytes()), []byte("onlyone"))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

// TestMultiV04RejectsOversizedSealedKey checks the v0x04 reader's bound on the
// per-recipient sealed-key length. A crafted header used to be able to claim
// up to 65535 bytes per recipient.
func TestMultiV04RejectsOversizedSealedKey(t *testing.T) {
	plaintext := []byte("v04 oom check")
	passwords := [][]byte{[]byte("pwd")}

	var buf bytes.Buffer
	if err := EncryptMulti(&buf, bytes.NewReader(plaintext), passwords, nil); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	// v0x04 header layout for the first recipient:
	//   magic(4) + version(1) + flags(1) + numRecipients(4) = 10
	//   saltLen(2) + salt(16) + Time(4) + Memory(4) + Threads(1) + KeyLen(4) + KeyNonce(12)
	//   = 43
	//   sealedKeyLen(2) = at offset 53
	const sealedKeyLenOff = 10 + 2 + 16 + 4 + 4 + 1 + 4 + 12
	if sealedKeyLenOff+2 > len(data) {
		t.Fatalf("data too short: %d bytes", len(data))
	}
	// Original value is keyLen(32) + GCM tag(16) = 48. Set to 1024.
	binary.LittleEndian.PutUint16(data[sealedKeyLenOff:sealedKeyLenOff+2], 1024)

	var decBuf bytes.Buffer
	err := Decrypt(&decBuf, bytes.NewReader(data), []byte("pwd"))
	if !errors.Is(err, ErrCorrupted) {
		t.Fatalf("expected ErrCorrupted, got %v", err)
	}
}
