package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

func TestInfoEncryptedMetadata(t *testing.T) {
	dir := t.TempDir()

	plaintext := []byte("test content for info")
	srcPath := filepath.Join(dir, "test.encrypted")

	cfg := &cipherlock.Config{
		SaltLen:  16,
		Time:     1,
		Memory:   65536,
		Threads:  1,
		KeyLen:   32,
		Checksum: false,
		FileMeta: &cipherlock.FileMeta{
			Name: "original.txt",
			Size: int64(len(plaintext)),
		},
	}

	var encBuf bytes.Buffer
	if err := cipherlock.EncryptStreamV2(&encBuf, bytes.NewReader(plaintext), testPassword, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, encBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	origEnv := infoPasswordEnv
	infoPasswordEnv = ""
	origFD := infoPasswordFD
	infoPasswordFD = ""
	origStdin := infoPasswordStdin
	infoPasswordStdin = false
	defer func() {
		infoPasswordEnv = origEnv
		infoPasswordFD = origFD
		infoPasswordStdin = origStdin
	}()

	var outBuf bytes.Buffer
	infoCmd.SetOut(&outBuf)
	defer func() { infoCmd.SetOut(nil) }()

	if err := infoCmd.RunE(infoCmd, []string{srcPath}); err != nil {
		t.Fatalf("info failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "File:") {
		t.Error("output should contain 'File:'")
	}
	if !strings.Contains(output, "Metadata: encrypted") {
		t.Error("output should contain 'Metadata: encrypted'")
	}
}

func TestInfoWithPassword(t *testing.T) {
	dir := t.TempDir()

	plaintext := []byte("test content for info with password")
	srcPath := filepath.Join(dir, "test2.encrypted")

	cfg := &cipherlock.Config{
		SaltLen:  16,
		Time:     1,
		Memory:   65536,
		Threads:  1,
		KeyLen:   32,
		Checksum: false,
		FileMeta: &cipherlock.FileMeta{
			Name: "original.txt",
			Size: int64(len(plaintext)),
		},
	}

	var encBuf bytes.Buffer
	if err := cipherlock.EncryptStreamV2(&encBuf, bytes.NewReader(plaintext), testPassword, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, encBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CIPHERLOCK_TEST_PW", string(testPassword))
	origEnv := infoPasswordEnv
	infoPasswordEnv = "CIPHERLOCK_TEST_PW"
	defer func() { infoPasswordEnv = origEnv }()

	var outBuf bytes.Buffer
	infoCmd.SetOut(&outBuf)
	defer func() { infoCmd.SetOut(nil) }()

	if err := infoCmd.RunE(infoCmd, []string{srcPath}); err != nil {
		t.Fatalf("info with password failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "File:") {
		t.Error("output should contain 'File:'")
	}
	if !strings.Contains(output, "Name:     original.txt") {
		t.Errorf("output should contain filename, got:\n%s", output)
	}
	if !strings.Contains(output, "Size:") {
		t.Error("output should contain 'Size:'")
	}
	if !strings.Contains(output, "Modified:") {
		t.Error("output should contain 'Modified:'")
	}
}
