package cipherlock

import (
	"fmt"
	"time"
)

// DefaultChunkSize is the default chunk size (64 KB) used for stream encryption.
const DefaultChunkSize = 64 * 1024

// FileMeta contains metadata about an encrypted file including its name, size, and modification time.
type FileMeta struct {
	Name      string
	Size      int64
	ModTime   time.Time
	ExpiresAt time.Time
}

// Profile defines Argon2id parameters that can be applied to a Config.
// Fields are JSON-tagged for serialization.
type Profile struct {
	Time     uint32 `json:"time"`
	Memory   uint32 `json:"memory"`
	Threads  uint8  `json:"threads"`
	Checksum bool   `json:"checksum"`
}

// Config holds encryption parameters including Argon2id key derivation settings,
// checksum behavior, chunk size, and optional file metadata.
type Config struct {
	SaltLen   int
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	Checksum  bool
	ChunkSize int
	FileMeta  *FileMeta
}

// ApplyProfile applies non-zero Profile fields to the Config.
// Only Time, Memory, Threads, and Checksum are applied; zero values are skipped.
func (c *Config) ApplyProfile(p *Profile) {
	if p == nil {
		return
	}
	if p.Time != 0 {
		c.Time = p.Time
	}
	if p.Memory != 0 {
		c.Memory = p.Memory
	}
	if p.Threads != 0 {
		c.Threads = p.Threads
	}
	c.Checksum = p.Checksum
}

// DefaultConfig is the default configuration used when a nil config is passed.
// It uses Argon2id with time=3, memory=64MB, threads=4, 16-byte salt, 32-byte key,
// and 64KB chunk size with no checksum.
var DefaultConfig = &Config{
	SaltLen:   16,
	Time:      3,
	Memory:    64 * 1024,
	Threads:   4,
	KeyLen:    32,
	ChunkSize: DefaultChunkSize,
}

// Validate checks that all Config fields are within valid bounds.
// Returns nil if the configuration is valid, or ErrConfigInvalid
// wrapping a descriptive message if not.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.SaltLen < 8 || c.SaltLen > maxSaltLen {
		return fmt.Errorf("%w: SaltLen must be between 8 and %d, got %d", ErrConfigInvalid, maxSaltLen, c.SaltLen)
	}
	if c.KeyLen < 16 || c.KeyLen > maxKeyLen {
		return fmt.Errorf("%w: KeyLen must be between 16 and %d, got %d", ErrConfigInvalid, maxKeyLen, c.KeyLen)
	}
	if c.Time < 1 || c.Time > maxTime {
		return fmt.Errorf("%w: Time must be between 1 and %d, got %d", ErrConfigInvalid, maxTime, c.Time)
	}
	if c.Memory < 1 || c.Memory > maxMemory {
		return fmt.Errorf("%w: Memory must be between 1 and %d, got %d", ErrConfigInvalid, maxMemory, c.Memory)
	}
	if c.Threads < 1 || c.Threads > maxThreads {
		return fmt.Errorf("%w: Threads must be between 1 and %d, got %d", ErrConfigInvalid, maxThreads, c.Threads)
	}
	if c.ChunkSize < 1 || c.ChunkSize > maxChunkSize {
		return fmt.Errorf("%w: ChunkSize must be between 1 and %d, got %d", ErrConfigInvalid, maxChunkSize, c.ChunkSize)
	}
	return nil
}
