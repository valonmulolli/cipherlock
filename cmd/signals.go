package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var (
	tempMu    sync.Mutex
	tempFiles []string
)

func trackTempFile(path string) {
	tempMu.Lock()
	tempFiles = append(tempFiles, path)
	tempMu.Unlock()
}

func untrackTempFile(path string) {
	tempMu.Lock()
	for i, p := range tempFiles {
		if p == path {
			tempFiles = append(tempFiles[:i], tempFiles[i+1:]...)
			break
		}
	}
	tempMu.Unlock()
}

func cleanupTempFiles() {
	tempMu.Lock()
	for _, p := range tempFiles {
		os.Remove(p)
	}
	tempFiles = nil
	tempMu.Unlock()
}

func init() {
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		cleanupTempFiles()
		os.Exit(1)
	}()
}

// inPlaceWrite performs an in-place write that is SIGINT-safe.
// It renames original to .cipherlock-bak, creates a temp file, calls writeFn
// with the temp file and bak paths, and on success renames temp over the original.
// If the operation fails, the original is restored from the backup.
// keepBak controls whether .cipherlock-bak is preserved or shredded.
func inPlaceWrite(srcPath string, keepBak bool, writeFn func(tmpPath, bakPath string) error) error {
	if backup {
		if err := copyFile(srcPath, srcPath+".bak"); err != nil {
			return err
		}
	}

	bak := srcPath + ".cipherlock-bak"
	if err := os.Rename(srcPath, bak); err != nil {
		return fmt.Errorf("rename to backup: %w", err)
	}

	tmp := srcPath + ".tmp"
	trackTempFile(tmp)

	if err := writeFn(tmp, bak); err != nil {
		os.Remove(tmp)
		untrackTempFile(tmp)
		if rerr := os.Rename(bak, srcPath); rerr != nil {
			return fmt.Errorf("write failed (%w) and restore failed (%v); data in %s", err, rerr, bak)
		}
		return err
	}

	if err := os.Rename(tmp, srcPath); err != nil {
		os.Remove(tmp)
		untrackTempFile(tmp)
		if rerr := os.Rename(bak, srcPath); rerr != nil {
			return fmt.Errorf("rename failed (%w) and restore failed (%v); data in %s", err, rerr, bak)
		}
		return err
	}
	untrackTempFile(tmp)

	if keepBak {
		_ = os.Rename(bak, srcPath+".bak")
	} else {
		if sderr := cipherlock.Shred(bak); sderr != nil {
			return fmt.Errorf("shred backup failed: %w", sderr)
		}
	}
	return nil
}
