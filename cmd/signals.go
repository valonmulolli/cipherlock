package cmd

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
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
