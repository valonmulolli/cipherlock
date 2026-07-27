package cmd

import (
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const keychainService = "cipherlock"

func keychainGet(account string) (string, error) {
	return keyring.Get(keychainService, account)
}

func keychainSet(account, password string) error {
	return keyring.Set(keychainService, account, password)
}

func getKeychainAccount(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}
	return resolved
}

func savePasswordsToKeychain(paths []string, passwords [][]byte) {
	if len(passwords) == 0 {
		return
	}
	for _, p := range paths {
		_ = keychainSet(getKeychainAccount(p), string(passwords[0]))
	}
	for _, pwd := range passwords {
		clear(pwd)
	}
}
