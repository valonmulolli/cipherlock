package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestShowKDF(t *testing.T) {
	origQuiet := quiet
	t.Cleanup(func() { quiet = origQuiet })

	quiet = false
	stop := showKDF()
	if stop == nil {
		t.Fatal("showKDF returned nil when quiet=false")
	}
	stop()

	quiet = true
	stop = showKDF()
	if stop == nil {
		t.Fatal("showKDF returned nil when quiet=true")
	}
	stop()
}

func TestProgressReaderReturnsOriginalWhenQuiet(t *testing.T) {
	origQuiet := quiet
	t.Cleanup(func() { quiet = origQuiet })

	quiet = true
	r := strings.NewReader("test")
	pr := progressReader(r, 100, "testing")
	if pr != r {
		t.Error("progressReader should return original reader when quiet=true")
	}
}

func TestProgressReaderReturnsOriginalWhenSizeZero(t *testing.T) {
	origQuiet := quiet
	t.Cleanup(func() { quiet = origQuiet })

	quiet = false
	r := strings.NewReader("test")
	pr := progressReader(r, 0, "testing")
	if pr != r {
		t.Error("progressReader should return original reader when size=0")
	}
}

func TestProgressReaderWrapsReader(t *testing.T) {
	origQuiet := quiet
	t.Cleanup(func() { quiet = origQuiet })

	quiet = false
	r := bytes.NewReader([]byte("test data for progress reader"))
	pr := progressReader(r, 100, "testing")
	if pr == io.Reader(r) {
		t.Error("progressReader should wrap reader when quiet=false and size>0")
	}

	data, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("reading from progress reader: %v", err)
	}
	if string(data) != "test data for progress reader" {
		t.Fatalf("got %q, want %q", string(data), "test data for progress reader")
	}
}
