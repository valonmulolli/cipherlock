package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

const (
	rekeyOldEnv = "CIPHERLOCK_TEST_OLD_PWD"
	rekeyNewEnv = "CIPHERLOCK_TEST_NEW_PWD"
)

func rekeyExec(t *testing.T, srcPath, oldPwd, newPwd string) {
	t.Helper()
	origOldVar := rekeyPasswordEnv
	origNewVar := rekeyNewPasswordEnv
	origForce := rekeyForce
	defer func() {
		rekeyPasswordEnv = origOldVar
		rekeyNewPasswordEnv = origNewVar
		rekeyForce = origForce
	}()
	rekeyPasswordEnv = rekeyOldEnv
	rekeyNewPasswordEnv = rekeyNewEnv
	rekeyForce = true
	t.Setenv(rekeyOldEnv, oldPwd)
	t.Setenv(rekeyNewEnv, newPwd)
	if err := rekeyCmd.RunE(rekeyCmd, []string{srcPath}); err != nil {
		t.Fatalf("rekey failed: %v", err)
	}
}

func rekeyFixture(t *testing.T, plaintext []byte, cfg *cipherlock.Config) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.encrypted")
	var buf bytes.Buffer
	if err := cipherlock.EncryptStream(&buf, bytes.NewReader(plaintext), testPassword, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return srcPath
}

func rekeyFixtureV2(t *testing.T, plaintext []byte, cfg *cipherlock.Config) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.encrypted")
	var buf bytes.Buffer
	if err := cipherlock.EncryptStreamV2(&buf, bytes.NewReader(plaintext), testPassword, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return srcPath
}

func rekeyFixtureMulti(t *testing.T, plaintext []byte, cfg *cipherlock.Config) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.encrypted")
	var buf bytes.Buffer
	if err := cipherlock.EncryptStreamMulti(&buf, bytes.NewReader(plaintext), [][]byte{testPassword}, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return srcPath
}

func decryptVerify(t *testing.T, encPath string, password []byte, want []byte) {
	t.Helper()
	f, err := os.Open(encPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if err := cipherlock.Decrypt(&buf, f, password); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("plaintext mismatch: got %q, want %q", buf.Bytes(), want)
	}
}

func decryptWithMetaVerify(t *testing.T, encPath string, password []byte, want []byte, metaName string) {
	t.Helper()
	f, err := os.Open(encPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var buf bytes.Buffer
	gotMeta, err := cipherlock.DecryptWithMeta(&buf, io.NewSectionReader(f, 0, 1<<62), password)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("plaintext mismatch: got %q, want %q", buf.Bytes(), want)
	}
	if gotMeta == nil {
		t.Fatal("expected FileMeta, got nil")
	}
	if gotMeta.Name != metaName {
		t.Errorf("meta.Name: got %q, want %q", gotMeta.Name, metaName)
	}
}

func TestRekeyV05(t *testing.T) {
	plaintext := []byte("hello rekey v05")
	cfg := &cipherlock.Config{SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32}
	src := rekeyFixture(t, plaintext, cfg)
	rekeyExec(t, src, string(testPassword), "new-password-456")
	decryptVerify(t, src, []byte("new-password-456"), plaintext)
}

func TestRekeyV06(t *testing.T) {
	plaintext := []byte("hello rekey v06")
	cfg := &cipherlock.Config{
		SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32,
		FileMeta: &cipherlock.FileMeta{Name: "original.txt", Size: int64(len(plaintext))},
	}
	src := rekeyFixtureV2(t, plaintext, cfg)
	rekeyExec(t, src, string(testPassword), "new-password-456")
	decryptVerify(t, src, []byte("new-password-456"), plaintext)
}

func TestRekeyV07(t *testing.T) {
	plaintext := []byte("hello rekey v07")
	cfg := &cipherlock.Config{
		SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32,
		FileMeta: &cipherlock.FileMeta{Name: "original.txt", Size: int64(len(plaintext))},
	}
	src := rekeyFixtureMulti(t, plaintext, cfg)
	rekeyExec(t, src, string(testPassword), "new-password-456")
	decryptVerify(t, src, []byte("new-password-456"), plaintext)
}

func TestRekeyInPlace(t *testing.T) {
	plaintext := []byte("in-place rekey")
	cfg := &cipherlock.Config{SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32}
	src := rekeyFixture(t, plaintext, cfg)
	rekeyExec(t, src, string(testPassword), "newer-password")
	decryptVerify(t, src, []byte("newer-password"), plaintext)
}

func TestRekeyWrongPassword(t *testing.T) {
	plaintext := []byte("wrong password test")
	cfg := &cipherlock.Config{SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32}
	src := rekeyFixture(t, plaintext, cfg)

	origOldVar := rekeyPasswordEnv
	origNewVar := rekeyNewPasswordEnv
	defer func() {
		rekeyPasswordEnv = origOldVar
		rekeyNewPasswordEnv = origNewVar
	}()
	rekeyPasswordEnv = rekeyOldEnv
	rekeyNewPasswordEnv = rekeyNewEnv
	t.Setenv(rekeyOldEnv, "wrong-password")
	t.Setenv(rekeyNewEnv, "new-password")

	if err := rekeyCmd.RunE(rekeyCmd, []string{src}); err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestRekeyCorruptedInput(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "corrupt.encrypted")
	if err := os.WriteFile(src, []byte("garbage not cipherlock"), 0644); err != nil {
		t.Fatal(err)
	}

	origOldVar := rekeyPasswordEnv
	origNewVar := rekeyNewPasswordEnv
	defer func() {
		rekeyPasswordEnv = origOldVar
		rekeyNewPasswordEnv = origNewVar
	}()
	rekeyPasswordEnv = rekeyOldEnv
	rekeyNewPasswordEnv = rekeyNewEnv
	t.Setenv(rekeyOldEnv, string(testPassword))
	t.Setenv(rekeyNewEnv, "new-password")

	if err := rekeyCmd.RunE(rekeyCmd, []string{src}); err == nil {
		t.Fatal("expected error for corrupted input, got nil")
	}
}

func TestRekeyFromEnvVar(t *testing.T) {
	plaintext := []byte("env var rekey")
	cfg := &cipherlock.Config{SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32}
	src := rekeyFixture(t, plaintext, cfg)
	rekeyExec(t, src, string(testPassword), "from-env-new")
	decryptVerify(t, src, []byte("from-env-new"), plaintext)
}

func TestRekeyNewFromKeyFile(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("key file new password")
	cfg := &cipherlock.Config{SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32}
	src := rekeyFixture(t, plaintext, cfg)
	keyFile := filepath.Join(dir, "new-pwd.txt")
	if err := os.WriteFile(keyFile, []byte("keyfile-password"), 0644); err != nil {
		t.Fatal(err)
	}

	origOldVar := rekeyPasswordEnv
	origNewKeyFile := newPwdFile
	defer func() {
		rekeyPasswordEnv = origOldVar
		newPwdFile = origNewKeyFile
	}()
	rekeyPasswordEnv = rekeyOldEnv
	newPwdFile = keyFile
	t.Setenv(rekeyOldEnv, string(testPassword))

	if err := rekeyCmd.RunE(rekeyCmd, []string{src}); err != nil {
		t.Fatalf("rekey with new key file failed: %v", err)
	}
	decryptVerify(t, src, []byte("keyfile-password"), plaintext)
}

func TestRekeyForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("force overwrite")
	cfg := &cipherlock.Config{SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32}
	src := rekeyFixture(t, plaintext, cfg)
	outPath := filepath.Join(dir, "preexisting.enc")
	if err := os.WriteFile(outPath, []byte("preexisting"), 0644); err != nil {
		t.Fatal(err)
	}

	origOldVar := rekeyPasswordEnv
	origNewVar := rekeyNewPasswordEnv
	origOut := rekeyOutput
	origForce := rekeyForce
	defer func() {
		rekeyPasswordEnv = origOldVar
		rekeyNewPasswordEnv = origNewVar
		rekeyOutput = origOut
		rekeyForce = origForce
	}()
	rekeyPasswordEnv = rekeyOldEnv
	rekeyNewPasswordEnv = rekeyNewEnv
	rekeyOutput = outPath
	rekeyForce = false
	t.Setenv(rekeyOldEnv, string(testPassword))
	t.Setenv(rekeyNewEnv, "forced-new")

	if err := rekeyCmd.RunE(rekeyCmd, []string{src}); err == nil {
		t.Fatal("expected error without --force when output exists")
	}

	rekeyForce = true
	if err := rekeyCmd.RunE(rekeyCmd, []string{src}); err != nil {
		t.Fatalf("rekey with --force should succeed: %v", err)
	}
	decryptVerify(t, outPath, []byte("forced-new"), plaintext)
}

func TestRekeyPreservesV06Meta(t *testing.T) {
	plaintext := []byte("preserve meta")
	meta := &cipherlock.FileMeta{
		Name:    "original.txt",
		Size:    int64(len(plaintext)),
		ModTime: time.Unix(0, 1700000000),
	}
	cfg := &cipherlock.Config{
		SaltLen: 16, Time: 1, Memory: 65536, Threads: 1, KeyLen: 32,
		FileMeta: meta,
	}
	src := rekeyFixtureV2(t, plaintext, cfg)
	rekeyExec(t, src, string(testPassword), "meta-test-new")
	decryptWithMetaVerify(t, src, []byte("meta-test-new"), plaintext, "original.txt")
}
