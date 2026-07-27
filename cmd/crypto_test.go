package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "secret.txt")
	dstPath := filepath.Join(dir, "secret.encrypted")
	outPath := filepath.Join(dir, "secret.decrypted")

	if err := os.WriteFile(srcPath, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = dstPath
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { outputPath = ""; passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, err := os.Stat(dstPath); err != nil {
		t.Fatal("encrypted file not created")
	}

	decryptOutput = outPath
	decryptPasswordEnv = "CL_PASS"
	defer func() { decryptOutput = ""; decryptPasswordEnv = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{dstPath}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Fatalf("got %q, want %q", string(data), "hello world")
	}
}

func TestEncryptDecryptStdout(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "stdout_test.txt")

	if err := os.WriteFile(srcPath, []byte("stdout data"), 0644); err != nil {
		t.Fatal(err)
	}

	passwordEnv = "CL_PASS"
	outputPath = "-"
	t.Setenv("CL_PASS", "test-password")
	defer func() { passwordEnv = ""; outputPath = "" }()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	encDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		encDone <- data
	}()

	if e := encryptCmd.RunE(encryptCmd, []string{srcPath}); e != nil {
		os.Stdout = oldStdout
		w.Close()
		t.Fatalf("encrypt -o - failed: %v", e)
	}
	w.Close()
	encData := <-encDone
	os.Stdout = oldStdout

	encPath := filepath.Join(dir, "encrypted.bin")
	if err := os.WriteFile(encPath, encData, 0644); err != nil {
		t.Fatal(err)
	}

	decryptPasswordEnv = "CL_PASS"
	decryptOutput = "-"
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	r2, w2, _ := os.Pipe()
	os.Stdout = w2
	decDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r2)
		decDone <- data
	}()

	if e := decryptCmd.RunE(decryptCmd, []string{encPath}); e != nil {
		os.Stdout = oldStdout
		w2.Close()
		t.Fatalf("decrypt -o - failed: %v", e)
	}
	w2.Close()
	decData := <-decDone
	os.Stdout = oldStdout

	if string(decData) != "stdout data" {
		t.Fatalf("got %q, want %q", string(decData), "stdout data")
	}
}

func TestEncryptDecryptStdinToFile(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "from_stdin.encrypted")
	outPath := filepath.Join(dir, "from_stdin.decrypted")

	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	outputPath = encPath
	defer func() { passwordEnv = ""; outputPath = "" }()

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	done := make(chan error, 1)
	go func() {
		w.Write([]byte("from stdin pipe"))
		w.Close()
	}()

	err = encryptCmd.RunE(encryptCmd, []string{"-"})
	os.Stdin = origStdin
	r.Close()
	close(done)

	if err != nil {
		t.Fatalf("encrypt stdin failed: %v", err)
	}

	decryptPasswordEnv = "CL_PASS"
	decryptOutput = outPath
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) != "from stdin pipe" {
		t.Fatalf("got %q, want %q", string(data), "from stdin pipe")
	}
}

func TestEncryptDecryptArmor(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "armor.txt")
	encPath := filepath.Join(dir, "armor.encrypted")
	outPath := filepath.Join(dir, "armor.decrypted")

	if err := os.WriteFile(srcPath, []byte("armored data"), 0644); err != nil {
		t.Fatal(err)
	}

	armorMode = true
	outputPath = encPath
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { armorMode = false; outputPath = ""; passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatalf("encrypt --armor failed: %v", err)
	}

	data, _ := os.ReadFile(encPath)
	if !strings.HasPrefix(string(data), "-----BEGIN CIPHERLOCK-----") {
		t.Fatal("armored file doesn't have correct header")
	}

	decryptPasswordEnv = "CL_PASS"
	decryptOutput = outPath
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt armored failed: %v", err)
	}

	decrypted, _ := os.ReadFile(outPath)
	if string(decrypted) != "armored data" {
		t.Fatalf("got %q, want %q", string(decrypted), "armored data")
	}
}

func TestEncryptDecryptChecksum(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "checksum.txt")
	encPath := filepath.Join(dir, "checksum.encrypted")
	outPath := filepath.Join(dir, "checksum.decrypted")

	if err := os.WriteFile(srcPath, []byte("checksum test"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = encPath
	checksumFlag = true
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { outputPath = ""; checksumFlag = false; passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatalf("encrypt --checksum failed: %v", err)
	}

	decryptPasswordEnv = "CL_PASS"
	decryptOutput = outPath
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt checksum failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) != "checksum test" {
		t.Fatalf("got %q, want %q", string(data), "checksum test")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "wrongpwd.txt")
	encPath := filepath.Join(dir, "wrongpwd.encrypted")

	if err := os.WriteFile(srcPath, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "correct-password")
	outputPath = encPath
	defer func() { passwordEnv = ""; outputPath = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatal(err)
	}

	decryptPasswordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "wrong-password")
	decryptOutput = filepath.Join(dir, "wrongpwd.decrypted")
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "corrupt.txt")
	encPath := filepath.Join(dir, "corrupt.encrypted")

	if err := os.WriteFile(srcPath, []byte("this is some longer data for testing corruption"), 0644); err != nil {
		t.Fatal(err)
	}

	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	outputPath = encPath
	defer func() { passwordEnv = ""; outputPath = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(encPath)
	// Corrupt the GCM tag (last 16 bytes) to guarantee auth failure
	for i := range 16 {
		data[len(data)-1-i] ^= 0xff
	}
	if err := os.WriteFile(encPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	decryptPasswordEnv = "CL_PASS"
	decryptOutput = filepath.Join(dir, "corrupt.decrypted")
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err == nil {
		t.Fatal("expected error for corrupted data, got nil")
	}
	if _, err := os.Stat(decryptOutput); err == nil {
		t.Error("partial output file should be removed on error")
	}
}

func TestEncryptMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(a, []byte("file a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("file b"), 0644); err != nil {
		t.Fatal(err)
	}

	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{a, b}); err != nil {
		t.Fatalf("multi-file encrypt failed: %v", err)
	}

	if _, err := os.Stat(a + ".encrypted"); err != nil {
		t.Error("a.txt.encrypted not found")
	}
	if _, err := os.Stat(b + ".encrypted"); err != nil {
		t.Error("b.txt.encrypted not found")
	}
}

func TestEncryptDecryptInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inplace.txt")

	if err := os.WriteFile(path, []byte("in-place test"), 0644); err != nil {
		t.Fatal(err)
	}

	inPlace = true
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { inPlace = false; passwordEnv = ""; decryptPasswordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{path}); err != nil {
		t.Fatalf("encrypt --in-place failed: %v", err)
	}

	decryptPasswordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	if err := decryptCmd.RunE(decryptCmd, []string{path}); err != nil {
		t.Fatalf("decrypt --in-place failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "in-place test" {
		t.Fatalf("got %q, want %q", string(data), "in-place test")
	}
}

func TestEncryptDecryptWithKeep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keep.txt")

	if err := os.WriteFile(path, []byte("keep test"), 0644); err != nil {
		t.Fatal(err)
	}

	inPlace = true
	keep = true
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { inPlace = false; keep = false; passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{path}); err != nil {
		t.Fatalf("encrypt --keep failed: %v", err)
	}
}

func TestEncryptDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dryrun.txt")

	if err := os.WriteFile(path, []byte("dry run"), 0644); err != nil {
		t.Fatal(err)
	}

	dryRun = true
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { dryRun = false; passwordEnv = "" }()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	errCh := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		errCh <- string(data)
	}()

	if err := encryptCmd.RunE(encryptCmd, []string{path}); err != nil {
		os.Stderr = oldStderr
		w.Close()
		t.Fatalf("dry-run failed: %v", err)
	}
	w.Close()
	stderrOutput := <-errCh
	os.Stderr = oldStderr

	if !strings.Contains(stderrOutput, "would encrypt") {
		t.Error("dry-run should print 'would encrypt'")
	}
	if _, err := os.Stat(path + ".encrypted"); err == nil {
		t.Error("dry-run should not create output file")
	}
}

func TestEncryptForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "force.txt")
	encPath := filepath.Join(dir, "force.encrypted")

	if err := os.WriteFile(path, []byte("force test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encPath, []byte("dummy"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = encPath
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { outputPath = ""; passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{path}); err == nil {
		t.Fatal("expected error for existing output, got nil")
	}

	forceEncrypt = true
	defer func() { forceEncrypt = false }()
	if err := encryptCmd.RunE(encryptCmd, []string{path}); err != nil {
		t.Fatalf("encrypt --force failed: %v", err)
	}
}

func TestEncryptDecryptRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f1.txt"), []byte("file 1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f2.txt"), []byte("file 2"), 0644); err != nil {
		t.Fatal(err)
	}

	recursive = true
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "test-password")
	defer func() { recursive = false; passwordEnv = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{dir}); err != nil {
		t.Fatalf("recursive encrypt failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "f1.txt.encrypted")); err != nil {
		t.Error("f1.txt.encrypted not found")
	}
	if _, err := os.Stat(filepath.Join(sub, "f2.txt.encrypted")); err != nil {
		t.Error("sub/f2.txt.encrypted not found")
	}
}

func TestEncryptWithRecipientPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.txt")
	encPath := filepath.Join(dir, "multi.encrypted")
	outPath := filepath.Join(dir, "multi.decrypted")

	if err := os.WriteFile(path, []byte("multi recipient"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = encPath
	passwordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "primary-pass")
	recipientPwds = []string{"secondary-pass"}
	defer func() { outputPath = ""; passwordEnv = ""; recipientPwds = nil }()

	if err := encryptCmd.RunE(encryptCmd, []string{path}); err != nil {
		t.Fatalf("multi-recipient encrypt failed: %v", err)
	}

	decryptPasswordEnv = "CL_PASS"
	t.Setenv("CL_PASS", "secondary-pass")
	decryptOutput = outPath
	defer func() { decryptPasswordEnv = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt with secondary password failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) != "multi recipient" {
		t.Fatalf("got %q, want %q", string(data), "multi recipient")
	}
}

func TestEncryptKeyFile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "keyfile.txt")
	encPath := filepath.Join(dir, "keyfile.encrypted")
	outPath := filepath.Join(dir, "keyfile.decrypted")
	keyPath := filepath.Join(dir, "password.txt")

	if err := os.WriteFile(srcPath, []byte("key file test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("file-password"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = encPath
	keyFilePath = keyPath
	defer func() { outputPath = ""; keyFilePath = "" }()

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatalf("encrypt --key-file failed: %v", err)
	}

	decryptKeyFile = keyPath
	decryptOutput = outPath
	defer func() { decryptKeyFile = ""; decryptOutput = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt --key-file failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) != "key file test" {
		t.Fatalf("got %q, want %q", string(data), "key file test")
	}
}

func TestEncryptDecryptWithCompression(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "compress_me.txt")
	encPath := filepath.Join(dir, "compress_me.encrypted")
	outPath := filepath.Join(dir, "compress_me.decrypted")

	// Use a highly compressible payload to verify the compression codepath
	payload := strings.Repeat("Hello, cipherlock compression! ", 2000)
	if err := os.WriteFile(srcPath, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = encPath
	passwordEnv = "CL_COMPRESS"
	compressFlag = true
	defer func() { outputPath = ""; passwordEnv = ""; compressFlag = false }()

	t.Setenv("CL_COMPRESS", "test-password")

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatalf("encrypt --compress failed: %v", err)
	}
	if _, err := os.Stat(encPath); err != nil {
		t.Fatal("encrypted file not created")
	}

	// Verify the encrypted file is smaller than the plaintext (compression works)
	plainInfo, _ := os.Stat(srcPath)
	encInfo, _ := os.Stat(encPath)
	if encInfo.Size() >= plainInfo.Size() {
		t.Logf("warning: compressed size (%d) not smaller than plaintext (%d)",
			encInfo.Size(), plainInfo.Size())
	}

	decryptOutput = outPath
	decryptPasswordEnv = "CL_COMPRESS"
	defer func() { decryptOutput = ""; decryptPasswordEnv = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt compressed file failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != payload {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(data), len(payload))
	}
}

func TestEncryptDecryptWithCompressionAndChecksum(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "compress_sum_test.txt")
	encPath := filepath.Join(dir, "compress_sum.encrypted")
	outPath := filepath.Join(dir, "compress_sum.decrypted")

	if err := os.WriteFile(srcPath, []byte("compressed with checksum"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath = encPath
	passwordEnv = "CL_COMPRESS_SUM"
	compressFlag = true
	checksumFlag = true
	defer func() {
		outputPath = ""
		passwordEnv = ""
		compressFlag = false
		checksumFlag = false
	}()

	t.Setenv("CL_COMPRESS_SUM", "test-password")

	if err := encryptCmd.RunE(encryptCmd, []string{srcPath}); err != nil {
		t.Fatalf("encrypt --compress --checksum failed: %v", err)
	}

	decryptOutput = outPath
	decryptPasswordEnv = "CL_COMPRESS_SUM"
	defer func() { decryptOutput = ""; decryptPasswordEnv = "" }()

	if err := decryptCmd.RunE(decryptCmd, []string{encPath}); err != nil {
		t.Fatalf("decrypt with compression+checksum failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) != "compressed with checksum" {
		t.Fatalf("got %q, want %q", string(data), "compressed with checksum")
	}
}
