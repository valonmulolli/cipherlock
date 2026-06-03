package cipherlock

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func metaConfig(meta *FileMeta) *Config {
	cfg := *DefaultConfig
	cfg.FileMeta = meta
	return &cfg
}

func TestDecryptWithMetaV06(t *testing.T) {
	meta := &FileMeta{
		Name:    "report-2024.pdf",
		ModTime: time.Unix(1700000000, 0),
	}
	plaintext := []byte("encrypted bytes")
	var buf bytes.Buffer
	if err := EncryptStreamV2(&buf, bytes.NewReader(plaintext), []byte("pw"), metaConfig(meta)); err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	gotMeta, err := DecryptWithMeta(&got, bytes.NewReader(buf.Bytes()), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta == nil {
		t.Fatal("expected non-nil FileMeta for v0x06 source")
	}
	if gotMeta.Name != meta.Name {
		t.Errorf("name: got %q want %q", gotMeta.Name, meta.Name)
	}
	if !gotMeta.ModTime.Equal(meta.ModTime) {
		t.Errorf("modtime: got %v want %v", gotMeta.ModTime, meta.ModTime)
	}
	if !bytes.Equal(got.Bytes(), plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptWithMetaV07(t *testing.T) {
	meta := &FileMeta{Name: "shared.txt", ModTime: time.Unix(1710000000, 0)}
	plaintext := []byte("multi-recipient body")
	var buf bytes.Buffer
	cfg := *DefaultConfig
	cfg.FileMeta = meta
	if err := EncryptStreamMulti(&buf, bytes.NewReader(plaintext), [][]byte{[]byte("a"), []byte("b")}, &cfg); err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	gotMeta, err := DecryptStreamMultiFromReader(&got, bytes.NewReader(buf.Bytes()), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta == nil {
		t.Fatal("expected non-nil FileMeta for v0x07 source")
	}
	if gotMeta.Name != meta.Name {
		t.Errorf("name: got %q want %q", gotMeta.Name, meta.Name)
	}
}

func TestDecryptWithMetaNilForV05(t *testing.T) {
	plaintext := []byte("v0x05 body")
	var buf bytes.Buffer
	if err := EncryptStream(&buf, bytes.NewReader(plaintext), []byte("pw"), DefaultConfig); err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	gotMeta, err := DecryptWithMeta(&got, bytes.NewReader(buf.Bytes()), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta != nil {
		t.Errorf("v0x05 should return nil FileMeta, got %+v", gotMeta)
	}
}

// TestCanonicalEntryPoints documents and exercises the three entry points
// that new code should reach for:
//
//   - EncryptStream      -> v0x05 (single password, streaming, no metadata)
//   - EncryptStreamV2    -> v0x06 (single password, streaming, optional encrypted metadata)
//   - EncryptStreamMulti -> v0x07 (multiple passwords, streaming, optional encrypted metadata)
//
// All three round-trip through the v0x06/v0x07-aware DecryptWithMeta helper.
func TestCanonicalEntryPoints(t *testing.T) {
	plaintext := bytes.Repeat([]byte("entry point"), 16)
	pw := []byte("secret")
	meta := &FileMeta{Name: "doc.txt", ModTime: time.Unix(1700000000, 0)}

	t.Run("v0x05 no meta", func(t *testing.T) {
		var buf bytes.Buffer
		if err := EncryptStream(&buf, bytes.NewReader(plaintext), pw, DefaultConfig); err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		m, err := DecryptWithMeta(&got, bytes.NewReader(buf.Bytes()), pw)
		if err != nil {
			t.Fatal(err)
		}
		if m != nil {
			t.Errorf("v0x05 returned non-nil meta: %+v", m)
		}
		if !bytes.Equal(got.Bytes(), plaintext) {
			t.Error("plaintext mismatch")
		}
	})

	t.Run("v0x06 with meta", func(t *testing.T) {
		var buf bytes.Buffer
		if err := EncryptStreamV2(&buf, bytes.NewReader(plaintext), pw, metaConfig(meta)); err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		m, err := DecryptWithMeta(&got, bytes.NewReader(buf.Bytes()), pw)
		if err != nil {
			t.Fatal(err)
		}
		if m == nil || m.Name != meta.Name {
			t.Errorf("meta roundtrip: %+v", m)
		}
	})

	t.Run("v0x07 multi-recipient with meta", func(t *testing.T) {
		pws := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		var buf bytes.Buffer
		cfg := *DefaultConfig
		cfg.FileMeta = meta
		if err := EncryptStreamMulti(&buf, bytes.NewReader(plaintext), pws, &cfg); err != nil {
			t.Fatal(err)
		}
		for _, p := range pws {
			var got bytes.Buffer
			m, err := DecryptWithMeta(&got, bytes.NewReader(buf.Bytes()), p)
			if err != nil {
				t.Fatalf("decrypt with %q: %v", p, err)
			}
			if m == nil || m.Name != meta.Name {
				t.Errorf("meta roundtrip via %q: %+v", p, m)
			}
			if !bytes.Equal(got.Bytes(), plaintext) {
				t.Errorf("plaintext mismatch via %q", p)
			}
		}
	})
}

// TestDeprecatedEncryptMultiStillWorks guards the v0x04 path so future
// deprecation can remove the comment without dropping the test: anyone
// removing the function itself is forced to also delete this test, which
// would fail to compile and be caught in review.
func TestDeprecatedEncryptMultiStillWorks(t *testing.T) {
	plaintext := []byte("legacy v0x04 body")
	pws := [][]byte{[]byte("one"), []byte("two")}
	var buf bytes.Buffer
	if err := EncryptMulti(&buf, bytes.NewReader(plaintext), pws, DefaultConfig); err != nil {
		t.Fatal(err)
	}
	for _, p := range pws {
		var got bytes.Buffer
		if err := Decrypt(&got, bytes.NewReader(buf.Bytes()), p); err != nil {
			t.Errorf("decrypt with %q: %v", p, err)
		}
	}
}

func TestDecryptFileWithMetaRestoresFilename(t *testing.T) {
	meta := &FileMeta{Name: "original.txt", ModTime: time.Unix(1720000000, 0)}
	plaintext := []byte("restore this")

	dir := t.TempDir()
	encPath := filepath.Join(dir, "blob.enc")

	encFile, err := os.Create(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncryptStreamV2(encFile, bytes.NewReader(plaintext), []byte("pw"), metaConfig(meta)); err != nil {
		encFile.Close()
		t.Fatal(err)
	}
	if err := encFile.Close(); err != nil {
		t.Fatal(err)
	}

	decPath := filepath.Join(dir, "restored.txt")
	gotMeta, err := DecryptFileWithMeta(encPath, decPath, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta == nil || gotMeta.Name != meta.Name {
		t.Errorf("FileMeta roundtrip failed: %+v", gotMeta)
	}

	body, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, plaintext) {
		t.Error("plaintext mismatch after file roundtrip")
	}
}
