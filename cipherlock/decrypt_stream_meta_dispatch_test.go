package cipherlock

import (
	"bytes"
	"testing"
	"time"
)

func TestDecryptStreamMetaDispatchesToV06(t *testing.T) {
	meta := &FileMeta{Name: "shared.docx", ModTime: time.Unix(1700000000, 0)}
	plaintext := []byte("v0x06 body for DecryptStreamMeta dispatch")
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), []byte("p"), metaConfig(meta)); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	gotMeta, err := DecryptStreamMeta(&dec, &enc, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta == nil {
		t.Fatal("DecryptStreamMeta should return meta for v0x06 source")
	}
	if gotMeta.Name != meta.Name {
		t.Errorf("meta name: got %q want %q", gotMeta.Name, meta.Name)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptStreamMetaDispatchesToV07(t *testing.T) {
	meta := &FileMeta{Name: "shared.txt", ModTime: time.Unix(1700000001, 0)}
	plaintext := []byte("v0x07 body for DecryptStreamMeta dispatch")
	var enc bytes.Buffer
	cfg := *DefaultConfig
	cfg.FileMeta = meta
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), [][]byte{[]byte("p")}, &cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	gotMeta, err := DecryptStreamMeta(&dec, &enc, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta == nil || gotMeta.Name != meta.Name {
		t.Errorf("DecryptStreamMeta v0x07: %+v", gotMeta)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptStreamMetaNilForV05(t *testing.T) {
	plaintext := []byte("v0x05 body")
	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(plaintext), []byte("p"), DefaultConfig); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	gotMeta, err := DecryptStreamMeta(&dec, &enc, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta != nil {
		t.Errorf("v0x05 with no meta should yield nil, got %+v", gotMeta)
	}
}
