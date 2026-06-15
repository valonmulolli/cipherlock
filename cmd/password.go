package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
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

// passwordSource bundles the optional password sources for resolvePassword.
type passwordSource struct {
	FD         string // --password-fd
	Env        string // --password-env
	KeyFile    string // --key-file
	KeychainOn bool   // enable keychain lookup
	KeychainAc string // keychain account name (when KeychainOn is true)
	GenPwd     bool   // generate a random password (encrypt only)
	Label      string // prompt label (e.g. "Enter password: ")
}

// resolvePassword resolves a single password from the first available source.
// Priority: keychain → FD → env var → key file → generated → prompt.
// When KeychainOn is true, KeychainAc is looked up in the system keychain.
// When GenPwd is true (and no earlier source matched), generates a 64-char
// hex-encoded password and prints it to stderr.
func resolvePassword(src passwordSource) ([]byte, error) {
	switch {
	case src.KeychainOn:
		pwdStr, err := keychainGet(src.KeychainAc)
		if err != nil {
			return nil, fmt.Errorf("keychain lookup failed: %w", err)
		}
		return []byte(pwdStr), nil
	case src.FD != "":
		return readPasswordFromFD(src.FD)
	case src.Env != "":
		return readPasswordFromEnv(src.Env)
	case src.KeyFile != "":
		pwd, err := os.ReadFile(src.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}
		return pwd, nil
	case src.GenPwd:
		pwd, err := generatePassword(32)
		if err != nil {
			return nil, err
		}
		if quiet {
			fmt.Fprintln(os.Stderr, string(pwd))
		} else {
			fmt.Fprintln(os.Stderr, "password:", string(pwd))
		}
		return pwd, nil
	default:
		fmt.Fprint(os.Stderr, src.Label)
		pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return pwd, err
	}
}
