package cipherlock //nolint:errcheck

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"
)

func Example() {
	dir, err := os.MkdirTemp("", "cipherlock")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "secret.txt")
	os.WriteFile(src, []byte("my secret data"), 0644)

	dst := src + ".encrypted"
	password := []byte("my-strong-password")

	if err := EncryptFile(src, dst, password, nil); err != nil {
		return
	}

	restored := filepath.Join(dir, "restored.txt")
	if err := DecryptFile(dst, restored, password); err != nil {
		return
	}
	// Output:
}

func ExampleEncrypt() {
	var buf bytes.Buffer
	err := Encrypt(&buf, bytes.NewReader([]byte("hello")), []byte("password"), nil)
	if err != nil {
		return
	}
	// Output:
}

func ExampleDecrypt() {
	var encrypted bytes.Buffer
	Encrypt(&encrypted, bytes.NewReader([]byte("hello")), []byte("password"), nil)

	var plaintext bytes.Buffer
	err := Decrypt(&plaintext, &encrypted, []byte("password"))
	if err != nil {
		return
	}
	// Output:
}

func ExampleEncryptStream() {
	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader([]byte("stream data")), []byte("password"), nil)
	if err != nil {
		return
	}
	// Output:
}

func ExampleEncryptMulti() {
	var buf bytes.Buffer
	passwords := [][]byte{[]byte("alice"), []byte("bob"), []byte("charlie")}
	src := bytes.NewReader([]byte("shared secret"))
	err := EncryptMulti(&buf, src, passwords, nil)
	if err != nil {
		return
	}
	// Output:
}

func ExampleReKeyFile() {
	dir, err := os.MkdirTemp("", "cipherlock")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "secret.txt")
	os.WriteFile(src, []byte("my secret data"), 0644)

	encrypted := src + ".encrypted"
	oldPass := []byte("old-password")
	EncryptFile(src, encrypted, oldPass, nil)

	newPass := []byte("new-password")
	if err := ReKeyFile(encrypted, "", oldPass, newPass, nil); err != nil {
		return
	}
	// Output:
}

func ExampleShred() {
	dir, err := os.MkdirTemp("", "cipherlock")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "secret.txt")
	os.WriteFile(path, []byte("sensitive data"), 0644)

	if err := Shred(path); err != nil {
		return
	}
	// Output:
}

func ExampleIsEncrypted() {
	dir, err := os.MkdirTemp("", "cipherlock")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	plainFile := filepath.Join(dir, "plain.txt")
	os.WriteFile(plainFile, []byte("public data"), 0644)

	encFile := plainFile + ".encrypted"
	EncryptFile(plainFile, encFile, []byte("password"), nil)

	ok, _ := IsEncrypted(encFile)
	_ = ok

	ok, _ = IsEncrypted(plainFile)
	_ = ok
	// Output:
}

func ExampleArmor() {
	var encrypted bytes.Buffer
	Encrypt(&encrypted, bytes.NewReader([]byte("armored data")), []byte("password"), nil)

	var armored bytes.Buffer
	if err := Armor(&armored, encrypted.Bytes()); err != nil {
		return
	}
	// Output:
}

func ExampleUnarmorBytes() {
	var encrypted bytes.Buffer
	Encrypt(&encrypted, bytes.NewReader([]byte("secret")), []byte("mypass"), nil)

	var armored bytes.Buffer
	Armor(&armored, encrypted.Bytes())

	raw, err := UnarmorBytes(armored.Bytes())
	if err != nil {
		return
	}

	var plaintext bytes.Buffer
	if err := Decrypt(&plaintext, bytes.NewReader(raw), []byte("mypass")); err != nil {
		return
	}
	// Output:
}

func ExampleEncryptContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var buf bytes.Buffer
	err := EncryptContext(ctx, &buf, bytes.NewReader([]byte("context data")), []byte("password"), nil)
	if err != nil {
		return
	}
	// Output:
}
