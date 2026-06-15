package cmd

import (
	"os"
	"strconv"
	"testing"
)

func TestReadPasswordFromEnv(t *testing.T) {
	const envVar = "CIPHERLOCK_TEST_PASSWORD"
	const expected = "test-password-value"

	t.Setenv(envVar, expected)

	pwd, err := readPasswordFromEnv(envVar)
	if err != nil {
		t.Fatalf("readPasswordFromEnv failed: %v", err)
	}
	if string(pwd) != expected {
		t.Fatalf("got %q, want %q", string(pwd), expected)
	}
}

func TestReadPasswordFromEnvEmptyOrUnset(t *testing.T) {
	const envVar = "CIPHERLOCK_TEST_EMPTY"

	t.Setenv(envVar, "")

	if _, err := readPasswordFromEnv(envVar); err == nil {
		t.Fatal("expected error for empty env var, got nil")
	}

	os.Unsetenv(envVar)
	if _, err := readPasswordFromEnv(envVar); err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
}

func TestReadPasswordFromFD(t *testing.T) {
	content := "password-from-fd\n"
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	pwd, err := readPasswordFromFD(strconv.Itoa(int(r.Fd())))
	r.Close()
	if err != nil {
		t.Fatalf("readPasswordFromFD failed: %v", err)
	}
	if string(pwd) != "password-from-fd" {
		t.Fatalf("got %q, want %q", string(pwd), "password-from-fd")
	}
}

func TestReadPasswordFromFDStripsNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write([]byte("pass\r\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	pwd, err := readPasswordFromFD(strconv.Itoa(int(r.Fd())))
	r.Close()
	if err != nil {
		t.Fatalf("readPasswordFromFD failed: %v", err)
	}
	if string(pwd) != "pass" {
		t.Fatalf("expected trimmed password, got %q", string(pwd))
	}
}

func TestReadPasswordFromFDInvalid(t *testing.T) {
	if _, err := readPasswordFromFD("not-a-number"); err == nil {
		t.Fatal("expected error for invalid fd string")
	}
	if _, err := readPasswordFromFD("-1"); err == nil {
		t.Fatal("expected error for negative fd")
	}
}

func TestReadPasswordFromFDNonExistent(t *testing.T) {
	// Use a high fd number that's unlikely to be open
	if _, err := readPasswordFromFD("1234"); err == nil {
		t.Fatal("expected error for non-existent fd")
	}
}
