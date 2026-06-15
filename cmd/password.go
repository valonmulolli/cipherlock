package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func readPasswordFromEnv(envVar string) ([]byte, error) {
	v := os.Getenv(envVar)
	if v == "" {
		return nil, fmt.Errorf("environment variable %q is empty or not set", envVar)
	}
	return []byte(v), nil
}

func readPasswordFromFD(fdStr string) ([]byte, error) {
	fdNum, err := strconv.Atoi(fdStr)
	if err != nil {
		return nil, fmt.Errorf("invalid file descriptor number %q: %w", fdStr, err)
	}
	if fdNum < 0 {
		return nil, fmt.Errorf("invalid file descriptor number: %d", fdNum)
	}

	f := os.NewFile(uintptr(fdNum), "password-fd")
	if f == nil {
		return nil, fmt.Errorf("invalid file descriptor: %d", fdNum)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading from file descriptor %d: %w", fdNum, err)
	}
	return []byte(strings.TrimRight(string(data), "\n\r")), nil
}
