package cipherlock

import (
	"crypto/rand"
	"os"
)

// Shred securely overwrites a file with random data followed by zeros, then removes it.
// Each pass is fsynced before the next step to flush page cache.
// This helps prevent recovery of sensitive data from disk.
//
// Note: Shred is best-effort. Copy-on-write filesystems (btrfs, ZFS), flash
// translation layers on SSDs, and wear-leveling NAND may retain stale copies
// of the overwritten data despite the sync.
func Shred(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	size := info.Size()
	if size == 0 {
		return os.Remove(path)
	}

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
	}

	f.Sync()
	return os.Remove(path)
}
