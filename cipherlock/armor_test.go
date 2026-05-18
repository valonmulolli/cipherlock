package cipherlock

import (
	"bytes"
	"strings"
	"testing"
)

func TestArmorRoundTrip(t *testing.T) {
	original := []byte("hello, this is some binary data \x00\x01\x02\xff")

	var armored bytes.Buffer
	if err := Armor(&armored, original); err != nil {
		t.Fatalf("Armor: %v", err)
	}

	output := armored.String()
	if !strings.HasPrefix(output, armorHeader+"\n") {
		t.Fatalf("expected header, got: %s", output[:40])
	}
	if !strings.HasSuffix(strings.TrimSpace(output), armorFooter) {
		t.Fatalf("expected footer, got: %s", output[len(output)-30:])
	}

	decoded, err := Unarmor(&armored)
	if err != nil {
		t.Fatalf("Unarmor: %v", err)
	}

	if !bytes.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch: got %x, want %x", decoded, original)
	}
}

func TestArmorLineWrapping(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}

	var armored bytes.Buffer
	if err := Armor(&armored, data); err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(armored.String(), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if line == "" {
			continue
		}
		if len(line) > armorLineLen {
			t.Fatalf("line exceeds %d chars: %d chars", armorLineLen, len(line))
		}
	}
}

func TestIsArmored(t *testing.T) {
	if !IsArmored([]byte(armorHeader + "\nbase64data\n" + armorFooter + "\n")) {
		t.Fatal("expected true for armored data")
	}
	if IsArmored([]byte("plain text")) {
		t.Fatal("expected false for plain text")
	}
}

func TestUnarmorErrors(t *testing.T) {
	_, err := UnarmorBytes([]byte("not armored"))
	if err != ErrNotArmored {
		t.Fatalf("expected ErrNotArmored, got: %v", err)
	}

	_, err = UnarmorBytes([]byte(armorHeader + "\n!!!invalid-base64!!!\n" + armorFooter + "\n"))
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestEncryptDecryptArmored(t *testing.T) {
	password := []byte("armor-test")
	plaintext := []byte("secret message for armored test")

	var encrypted bytes.Buffer
	if err := Encrypt(&encrypted, bytes.NewReader(plaintext), password, nil); err != nil {
		t.Fatal(err)
	}

	var armored bytes.Buffer
	if err := Armor(&armored, encrypted.Bytes()); err != nil {
		t.Fatal(err)
	}

	decoded, err := Unarmor(&armored)
	if err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	if err := Decrypt(&decrypted, bytes.NewReader(decoded), password); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatal("armored encrypt/decrypt round-trip failed")
	}
}
