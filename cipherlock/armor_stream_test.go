package cipherlock

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestArmorUnarmorRoundtripSmall(t *testing.T) {
	data := []byte("hello, world")
	var buf bytes.Buffer
	if err := Armor(&buf, data); err != nil {
		t.Fatal(err)
	}
	got, err := Unarmor(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("roundtrip: got %q want %q", got, data)
	}
}

func TestNewArmorWriterStreams(t *testing.T) {
	plaintext := make([]byte, 1024*1024) // 1 MiB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	aw := NewArmorWriter(&buf)
	chunk := plaintext[:1234]
	if _, err := aw.Write(chunk); err != nil {
		t.Fatal(err)
	}
	if _, err := aw.Write(plaintext[1234:]); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}

	// Stream the armored output back through NewUnarmorReader.
	ur, err := NewUnarmorReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(ur)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("streaming roundtrip mismatch")
	}
}

func TestNewUnarmorReaderEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Armor(&buf, []byte("")); err != nil {
		t.Fatal(err)
	}
	ur, err := NewUnarmorReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(ur)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d bytes", len(got))
	}
}

func TestNewUnarmorReaderNonArmoredPassesThrough(t *testing.T) {
	// When the input is not armored, NewUnarmorReader should return
	// the original reader unchanged so callers can branch uniformly.
	raw := []byte{0x43, 0x4C, 0x01, 0x02, 0x03, 0x04, 0x05} // not armorHeader
	ur, err := NewUnarmorReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(ur)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("non-armored input should pass through, got %q want %q", got, raw)
	}
}

func TestNewUnarmorReaderLargeChunked(t *testing.T) {
	plaintext := bytes.Repeat([]byte("ABCDEFGH"), 64*1024) // 512 KiB
	var buf bytes.Buffer
	aw := NewArmorWriter(&buf)
	// Write in 100-byte pieces to stress the line-wrapping logic.
	for i := 0; i < len(plaintext); i += 100 {
		end := i + 100
		if end > len(plaintext) {
			end = len(plaintext)
		}
		if _, err := aw.Write(plaintext[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	ur, err := NewUnarmorReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(ur)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("chunked roundtrip mismatch")
	}
}

func TestNewUnarmorReaderTruncated(t *testing.T) {
	// Input that starts with the header but never delivers the footer.
	// The reader should return ErrUnexpectedEOF so the caller doesn't hang.
	var buf bytes.Buffer
	buf.WriteString(armorHeader + "\n")
	buf.WriteString("SGVsbG8=\n") // "Hello"
	ur, err := NewUnarmorReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(ur)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF, got %v", err)
	}
	if !bytes.Equal(got, []byte("Hello")) {
		t.Errorf("truncated data: got %q want %q", got, "Hello")
	}
}

func TestArmorWriterCloseTwiceIsSafe(t *testing.T) {
	var buf bytes.Buffer
	aw := NewArmorWriter(&buf)
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Errorf("second Close should be no-op, got %v", err)
	}
}

func TestArmorWriterWriteAfterCloseFails(t *testing.T) {
	var buf bytes.Buffer
	aw := NewArmorWriter(&buf)
	_ = aw.Close()
	if _, err := aw.Write([]byte("x")); err == nil {
		t.Error("expected error writing to closed ArmorWriter")
	}
}
