package cipherlock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Threads     uint8  `json:"threads"`
	Checksum    bool   `json:"checksum"`
	Compression bool   `json:"compression"`
}

// Config holds encryption parameters including Argon2id key derivation settings,
// checksum behavior, chunk size, optional file metadata, and compression.
type Config struct {
	SaltLen     int
	Time        uint32
	Memory      uint32
	Threads     uint8
	KeyLen      uint32
	Checksum    bool
	ChunkSize   int
	FileMeta    *FileMeta
	Compression bool
}

// ApplyProfile applies non-zero Profile fields to the Config.
// Only Time, Memory, Threads, and Checksum are applied; zero values are skipped.
func (c *Config) ApplyProfile(p *Profile) {
	if p == nil {
		return
	}
	c.Compression = p.Compression
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

// ProfilesPath returns the path to the user's profiles.json file.
// The directory is created if it does not exist.
func ProfilesPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "cipherlock")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles.json"), nil
}

// LoadProfiles reads all saved configuration profiles from disk.
// Returns an empty map if no profiles have been saved yet.
func LoadProfiles() (map[string]Profile, error) {
	path, err := ProfilesPath()
	if err != nil {
		return make(map[string]Profile), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]Profile), nil
		}
		return nil, err
	}

	var store struct {
		Profiles map[string]Profile `json:"profiles"`
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Profiles == nil {
		store.Profiles = make(map[string]Profile)
	}
	return store.Profiles, nil
}

// ConfigBuilder provides a fluent API for constructing Config values.
// It starts with a copy of DefaultConfig and each With* method sets a field.
//
// Example:
//
//	config := cipherlock.NewConfigBuilder().
//	    WithMemory(128 * 1024).
//	    WithCompression().
//	    WithChecksum().
//	    MustBuild()
type ConfigBuilder struct {
	config Config
}

// NewConfigBuilder returns a new ConfigBuilder initialized with DefaultConfig values.
func NewConfigBuilder() *ConfigBuilder {
	def := *DefaultConfig
	return &ConfigBuilder{config: def}
}

// WithSaltLen sets the salt length in bytes.
func (b *ConfigBuilder) WithSaltLen(n int) *ConfigBuilder {
	b.config.SaltLen = n
	return b
}

// WithTime sets the Argon2id time parameter.
func (b *ConfigBuilder) WithTime(t uint32) *ConfigBuilder {
	b.config.Time = t
	return b
}

// WithMemory sets the Argon2id memory parameter in KB.
func (b *ConfigBuilder) WithMemory(memoryKB uint32) *ConfigBuilder {
	b.config.Memory = memoryKB
	return b
}

// WithThreads sets the Argon2id parallelism.
func (b *ConfigBuilder) WithThreads(t uint8) *ConfigBuilder {
	b.config.Threads = t
	return b
}

// WithKeyLen sets the derived key length in bytes.
func (b *ConfigBuilder) WithKeyLen(k uint32) *ConfigBuilder {
	b.config.KeyLen = k
	return b
}

// WithChunkSize sets the plaintext chunk size in bytes.
func (b *ConfigBuilder) WithChunkSize(n int) *ConfigBuilder {
	b.config.ChunkSize = n
	return b
}

// WithChecksum enables embedded SHA-256 checksum verification.
func (b *ConfigBuilder) WithChecksum() *ConfigBuilder {
	b.config.Checksum = true
	return b
}

// WithCompression enables zstd compression before encryption.
func (b *ConfigBuilder) WithCompression() *ConfigBuilder {
	b.config.Compression = true
	return b
}

// WithFileMeta attaches file metadata (name, size, modtime) to the config.
func (b *ConfigBuilder) WithFileMeta(meta *FileMeta) *ConfigBuilder {
	b.config.FileMeta = meta
	return b
}

// Build validates the config and returns it, or an error if validation fails.
func (b *ConfigBuilder) Build() (*Config, error) {
	if err := b.config.Validate(); err != nil {
		return nil, err
	}
	cp := b.config
	return &cp, nil
}

// MustBuild returns the config without validation.
// Use when you know the values are valid or want to rely on caller validation.
func (b *ConfigBuilder) MustBuild() *Config {
	cp := b.config
	return &cp
}

// SaveProfiles atomically writes all configuration profiles to disk.
func SaveProfiles(profiles map[string]Profile) error {
	if profiles == nil {
		profiles = make(map[string]Profile)
	}

	path, err := ProfilesPath()
	if err != nil {
		return err
	}

	store := struct {
		Profiles map[string]Profile `json:"profiles"`
	}{Profiles: profiles}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	// Write to a tempfile in the same directory then rename atomically,
	// so a concurrent reader never sees a partially-written file.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profiles-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Chmod(path, 0600)
}
