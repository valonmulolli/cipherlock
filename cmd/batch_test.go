package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

func TestBatchEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()

	plaintexts := []string{"hello a", "hello b"}
	var srcPaths []string
	for i, txt := range plaintexts {
		p := filepath.Join(dir, "file.txt")
		if i == 1 {
			p = filepath.Join(dir, "other.txt")
		}
		if err := os.WriteFile(p, []byte(txt), 0644); err != nil {
			t.Fatal(err)
		}
		srcPaths = append(srcPaths, p)
	}

	encDir := filepath.Join(dir, "encrypted")
	if err := os.MkdirAll(encDir, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &cipherlock.Config{
		SaltLen:  16,
		Time:     1,
		Memory:   65536,
		Threads:  1,
		KeyLen:   32,
		Checksum: false,
	}
	for i, src := range srcPaths {
		info, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(encDir, info.Name()+".encrypted")
		if err := encryptFile(src, dest, info, [][]byte{testPassword}, nil, cfg); err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
	}

	decDir := filepath.Join(dir, "decrypted")
	if err := os.MkdirAll(decDir, 0755); err != nil {
		t.Fatal(err)
	}

	encFiles, _ := filepath.Glob(filepath.Join(encDir, "*.encrypted"))
	if len(encFiles) != 2 {
		t.Fatalf("expected 2 encrypted files, got %d", len(encFiles))
	}

	for i, enc := range encFiles {
		info, err := os.Stat(enc)
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(decDir, filepath.Base(defaultDecryptPath(enc)))
		if err := decryptFile(enc, dest, info, testPassword); err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
	}

	for i, expected := range plaintexts {
		originalName := "file.txt"
		if i == 1 {
			originalName = "other.txt"
		}
		got, err := os.ReadFile(filepath.Join(decDir, originalName))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != expected {
			t.Fatalf("file %d: got %q, want %q", i, string(got), expected)
		}
	}
}

func TestBatchFlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		output  string
		outDir  string
		inPlace bool
		wantErr string
	}{
		{
			name:    "output_and_outdir_mutually_exclusive",
			args:    []string{"a.txt"},
			output:  "out.enc",
			outDir:  "/tmp/out",
			wantErr: "--output and --out-dir are mutually exclusive",
		},
		{
			name:    "inplace_and_output",
			args:    []string{"a.txt"},
			output:  "out.enc",
			inPlace: true,
			wantErr: "--in-place is mutually exclusive with --output and --out-dir",
		},
		{
			name:    "output_with_multiple_files",
			args:    []string{"a.txt", "b.txt"},
			output:  "out.enc",
			wantErr: "--output cannot be used with multiple input files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEncryptFlags(tt.args, tt.output, tt.outDir, tt.inPlace)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("got %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestDefaultDecryptPath(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"file.txt.encrypted", "file.txt"},
		{"dir.cipherlock", "dir"},
		{"foo.bar", "foo.bar.decrypted"},
		{"/path/to/doc.pdf.encrypted", "/path/to/doc.pdf"},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			got := defaultDecryptPath(tt.source)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRestoreMeta(t *testing.T) {
	dir := t.TempDir()

	plaintext := []byte("restore me")
	srcPath := filepath.Join(dir, "original.txt.encrypted")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	decPath := filepath.Join(dir, "original.txt")
	if err := os.WriteFile(decPath, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &cipherlock.Config{
		SaltLen: 16,
		Time:    1,
		Memory:  65536,
		Threads: 1,
		KeyLen:  32,
		FileMeta: &cipherlock.FileMeta{
			Name: "restored.txt",
			Size: 9,
		},
	}

	encPath := filepath.Join(dir, "wrapper.encrypted")
	f, err := os.Create(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cipherlock.EncryptStreamV2(f, bytes.NewReader(plaintext), testPassword, cfg); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	restoreMeta(encPath, decPath, testPassword, false)

	restoredPath := filepath.Join(dir, "restored.txt")
	_, err = os.Stat(restoredPath)
	if err != nil {
		t.Fatalf("restored file not found: %v", err)
	}
}

func TestIsAuthError(t *testing.T) {
	if !isAuthError(cipherlock.ErrAuthFailed) {
		t.Fatal("isAuthError(ErrAuthFailed) should be true")
	}
	if isAuthError(cipherlock.ErrInvalidFormat) {
		t.Fatal("isAuthError(ErrInvalidFormat) should be false")
	}
	if isAuthError(nil) {
		t.Fatal("isAuthError(nil) should be false")
	}
}

func TestCheckDecrypt(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("check me")
	srcPath := filepath.Join(dir, "test.encrypted")

	cfg := &cipherlock.Config{
		SaltLen: 16,
		Time:    1,
		Memory:  65536,
		Threads: 1,
		KeyLen:  32,
	}

	var buf bytes.Buffer
	if err := cipherlock.EncryptStream(&buf, bytes.NewReader(plaintext), testPassword, cfg); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(srcPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := checkDecrypt(srcPath, info, testPassword); err != nil {
		t.Fatalf("checkDecrypt with correct password: %v", err)
	}

	if err := checkDecrypt(srcPath, info, []byte("wrong")); err == nil {
		t.Fatal("expected error for wrong password")
	}
}
