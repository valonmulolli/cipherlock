package cipherlock

import (
	"bytes"
	"testing"
	"time"
)

func versionOf(t *testing.T, data []byte) byte {
	t.Helper()
	if len(data) < 5 {
		t.Fatalf("data too short: %d bytes", len(data))
	}
	if !bytes.Equal(data[:4], magic[:]) {
		t.Fatalf("not a cipherlock file")
	}
	return data[4]
}

func TestReKeyPreservesV05Format(t *testing.T) {
	plaintext := []byte("v0x05 rekey preserves format")
	oldPwd := []byte("a")
	newPwd := []byte("b")

	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(plaintext), oldPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(t, enc.Bytes()); got != formatVersionStream {
		t.Fatalf("input version: got 0x%02x want 0x%02x", got, formatVersionStream)
	}

	var rekeyed bytes.Buffer
	if err := ReKey(&rekeyed, &enc, oldPwd, newPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(t, rekeyed.Bytes()); got != formatVersionStream {
		t.Errorf("output version: got 0x%02x want 0x%02x (v0x05 must round-trip)", got, formatVersionStream)
	}

	// Verify decrypt still works.
	var dec bytes.Buffer
	if err := Decrypt(&dec, &rekeyed, newPwd); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestReKeyPreservesV06FormatAndMeta(t *testing.T) {
	plaintext := []byte("v0x06 rekey preserves format and metadata")
	oldPwd := []byte("a")
	newPwd := []byte("b")
	meta := &FileMeta{Name: "important.pdf", ModTime: time.Unix(1700000000, 0)}

	var enc bytes.Buffer
	cfg := *fastConfig()
	cfg.FileMeta = meta
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), oldPwd, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(t, enc.Bytes()); got != formatVersionStreamV2 {
		t.Fatalf("input version: got 0x%02x want 0x%02x", got, formatVersionStreamV2)
	}

	var rekeyed bytes.Buffer
	if err := ReKey(&rekeyed, &enc, oldPwd, newPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(t, rekeyed.Bytes()); got != formatVersionStreamV2 {
		t.Errorf("output version: got 0x%02x want 0x%02x (v0x06 must round-trip)", got, formatVersionStreamV2)
	}

	// Verify decrypt still works AND meta is preserved.
	var dec bytes.Buffer
	gotMeta, err := DecryptWithMeta(&dec, &rekeyed, newPwd)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}
	if gotMeta == nil {
		t.Fatal("FileMeta lost after ReKey of v0x06 source")
	}
	if gotMeta.Name != meta.Name {
		t.Errorf("meta name: got %q want %q", gotMeta.Name, meta.Name)
	}
}

func TestReKeyPreservesV07FormatAndMeta(t *testing.T) {
	plaintext := []byte("v0x07 rekey preserves format and metadata")
	oldPwd := []byte("a")
	newPwd := []byte("b")
	meta := &FileMeta{Name: "shared.docx", ModTime: time.Unix(1700000001, 0)}

	var enc bytes.Buffer
	cfg := *fastConfig()
	cfg.FileMeta = meta
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), [][]byte{oldPwd, []byte("also")}, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(t, enc.Bytes()); got != formatVersionStreamMulti {
		t.Fatalf("input version: got 0x%02x want 0x%02x", got, formatVersionStreamMulti)
	}

	var rekeyed bytes.Buffer
	if err := ReKey(&rekeyed, &enc, oldPwd, newPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(t, rekeyed.Bytes()); got != formatVersionStreamMulti {
		t.Errorf("output version: got 0x%02x want 0x%02x (v0x07 must round-trip)", got, formatVersionStreamMulti)
	}

	// Verify decrypt still works with the new password AND meta is preserved.
	// Note: only newPwd should work; the second recipient "also" should fail.
	var dec bytes.Buffer
	gotMeta, err := DecryptStreamMultiFromReader(&dec, &rekeyed, newPwd)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}
	if gotMeta == nil {
		t.Fatal("FileMeta lost after ReKey of v0x07 source")
	}
	if gotMeta.Name != meta.Name {
		t.Errorf("meta name: got %q want %q", gotMeta.Name, meta.Name)
	}

	// Sanity: the old "also" password should no longer decrypt.
	var dec2 bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec2, &rekeyed, []byte("also")); err == nil {
		t.Error("expected error decrypting with collapsed 'also' password")
	}
}

func TestReKeyV05NoMetaNoMetaLeak(t *testing.T) {
	// v0x05 input has no FileMeta. ReKey output should also have no meta.
	plaintext := []byte("plain v0x05 only")
	oldPwd := []byte("a")
	newPwd := []byte("b")

	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(plaintext), oldPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}
	var rekeyed bytes.Buffer
	if err := ReKey(&rekeyed, &enc, oldPwd, newPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	gotMeta, err := DecryptWithMeta(&dec, &rekeyed, newPwd)
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta != nil {
		t.Errorf("v0x05 rekey should not surface a meta, got %+v", gotMeta)
	}
}
