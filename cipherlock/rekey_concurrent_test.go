package cipherlock

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

var errPlaintextMismatch = errors.New("plaintext mismatch after concurrent rekey")

func TestReKeyConcurrent(t *testing.T) {
	plaintext := make([]byte, 1<<14)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	oldPwd := []byte("old")
	newPwd := []byte("new")

	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(plaintext), oldPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}

	src := enc.Bytes()
	var wg sync.WaitGroup
	errs := make(chan error, 16)

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			if err := ReKey(&buf, bytes.NewReader(src), oldPwd, newPwd, fastConfig()); err != nil {
				errs <- err
				return
			}
			var dec bytes.Buffer
			if _, err := DecryptWithMeta(&dec, &buf, newPwd); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(dec.Bytes(), plaintext) {
				errs <- errPlaintextMismatch
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
