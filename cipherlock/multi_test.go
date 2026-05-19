package cipherlock

import (
	"bytes"
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
