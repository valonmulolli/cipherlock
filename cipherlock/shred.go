package cipherlock

import (
	"crypto/rand"
	"os"
)

type ShredProgressFn func(pass, totalPasses int, bytesWritten, fileSize int64)

// Shred securely overwrites a file with random data followed by zeros, then removes it.
func Shred(path string) error {
	return ShredWith(path, nil)
}

// ShredWith is like Shred but calls fn after each write to report progress.
// fn may be nil.
func ShredWith(path string, fn ShredProgressFn) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	size := info.Size()
	if size == 0 {
		return os.Remove(path)
	}

	totalPasses := 2

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	random := make([]byte, 4096)
	remaining := size
	for remaining > 0 {
		if _, err := rand.Read(random); err != nil {
			f.Close() //nolint:errcheck
			return err
		}
		writeLen := int64(len(random))
		if writeLen > remaining {
			writeLen = remaining
		}
		if _, err := f.Write(random[:writeLen]); err != nil {
			f.Close() //nolint:errcheck
			return err
		}
		remaining -= writeLen
		if fn != nil {
			fn(1, totalPasses, size-remaining, size)
		}
	}

	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	zeros := make([]byte, 4096)
	f, err = os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	remaining = size
	for remaining > 0 {
		writeLen := int64(len(zeros))
		if writeLen > remaining {
			writeLen = remaining
		}
		if _, err := f.Write(zeros[:writeLen]); err != nil {
			return err
		}
		remaining -= writeLen
		if fn != nil {
			fn(2, totalPasses, size-remaining, size)
		}
	}

	if err := f.Sync(); err != nil {
		return err
	}
	return os.Remove(path)
}
