package cipherlock

import (
	"bytes"
	"testing"
)

func TestApplyProfileNilIsNoOp(t *testing.T) {
	cfg := *DefaultConfig
	cfg.Time = 7
	before := cfg
	cfg.ApplyProfile(nil)
	if cfg != before {
		t.Errorf("nil profile should not modify config: %+v -> %+v", before, cfg)
	}
}

func TestApplyProfileAppliesNonZero(t *testing.T) {
	cfg := *DefaultConfig
	p := &Profile{Time: 5, Memory: 32 * 1024, Threads: 2, Checksum: true}
	cfg.ApplyProfile(p)
	if cfg.Time != 5 {
		t.Errorf("Time: got %d want 5", cfg.Time)
	}
	if cfg.Memory != 32*1024 {
		t.Errorf("Memory: got %d want %d", cfg.Memory, 32*1024)
	}
	if cfg.Threads != 2 {
		t.Errorf("Threads: got %d want 2", cfg.Threads)
	}
	if !cfg.Checksum {
		t.Error("Checksum: got false want true")
	}
}

func TestApplyProfileSkipsZeroNumeric(t *testing.T) {
	cfg := *DefaultConfig
	cfg.Time = 7
	cfg.Memory = 16 * 1024
	cfg.Threads = 8

	cfg.ApplyProfile(&Profile{}) // all zero, only Checksum (bool) would be applied
	if cfg.Time != 7 {
		t.Errorf("Time should be preserved, got %d", cfg.Time)
	}
	if cfg.Memory != 16*1024 {
		t.Errorf("Memory should be preserved, got %d", cfg.Memory)
	}
	if cfg.Threads != 8 {
		t.Errorf("Threads should be preserved, got %d", cfg.Threads)
	}
}

func TestApplyProfileChecksumAlwaysApplied(t *testing.T) {
	cfg := *DefaultConfig
	cfg.Checksum = true
	cfg.ApplyProfile(&Profile{Checksum: false})
	if cfg.Checksum {
		t.Error("Profile{Checksum:false} should disable a previously-enabled checksum")
	}
}

func TestProfileDrivesFastConfigRoundtrip(t *testing.T) {
	fast := &Profile{Time: 1, Memory: 8 * 1024, Threads: 1}
	cfg := *DefaultConfig
	cfg.ApplyProfile(fast)

	plaintext := []byte("profile-driven fast config")
	var buf bytes.Buffer
	if err := EncryptStreamV2(&buf, bytes.NewReader(plaintext), []byte("pw"), &cfg); err != nil {
		t.Fatal(err)
	}

	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(buf.Bytes()), []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Error("roundtrip mismatch")
	}
}
