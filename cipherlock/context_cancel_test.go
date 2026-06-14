package cipherlock

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// slowReader returns data in small chunks, pausing between each to give
// the caller time to cancel mid-stream.
type slowReader struct {
	data   []byte
	offset int
	chunk  int
	delay  time.Duration
	mu     sync.Mutex
}

func (sr *slowReader) Read(p []byte) (int, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if sr.offset >= len(sr.data) {
		return 0, io.EOF
	}
	end := sr.offset + sr.chunk
	if end > len(sr.data) {
		end = len(sr.data)
	}
	n := copy(p, sr.data[sr.offset:end])
	sr.offset += n
	time.Sleep(sr.delay)
	return n, nil
}

func TestStreamCancelMidEncrypt(t *testing.T) {
	data := make([]byte, 1<<17)
	for i := range data {
		data[i] = byte(i)
	}

	sr := &slowReader{data: data, chunk: 1 << 12, delay: time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	var dst bytes.Buffer
	err := EncryptStreamContext(ctx, &dst, sr, []byte("pwd"), fastConfig())
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("expected context error, got: %v", err)
	}
}

func TestDecryptCancelMidStream(t *testing.T) {
	data := make([]byte, 1<<17)
	for i := range data {
		data[i] = byte(i)
	}

	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(data), []byte("pwd"), fastConfig()); err != nil {
		t.Fatal(err)
	}

	// Decrypt at normal speed but cancel context immediately after starting.
	// The decrypt goroutine should stop at the next chunk boundary.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	// Small sleep to ensure context fires before the decrypt loop finishes.
	time.Sleep(time.Millisecond)

	var dst bytes.Buffer
	err := DecryptStreamContext(ctx, &dst, &enc, []byte("pwd"))
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("expected context error, got: %v", err)
	}
}
