# cipherlock library

AES-256-GCM file encryption with Argon2id key derivation -- Go library API reference.

> import "github.com/valonmulolli/cipherlock/cipherlock"

## Contents

- [Quick start](#quick-start)
- [Encryption basics](#encryption-basics)
- [Configuration](#configuration)
- [Streaming API](#streaming-api)
- [Key management](#key-management)
- [Asymmetric encryption](#asymmetric-encryption)
- [Multi-recipient encryption](#multi-recipient-encryption)
- [Profiles](#profiles)
- [Format detection](#format-detection)
- [Directory encryption](#directory-encryption)
- [Re-keying](#re-keying)
- [Metadata](#metadata)
- [Error handling](#error-handling)
- [Best practices](#best-practices)
- [Complete API reference](#complete-api-reference)

---

## Quick start

```go
package main

import (
    "bytes"
    "fmt"
    "log"
    "os"

    "github.com/valonmulolli/cipherlock/cipherlock"
)

func main() {
    password := []byte("hunter2")

    // --- Encrypt ---
    plaintext := bytes.NewReader([]byte("Hello, cipherlock!"))
    var ciphertext bytes.Buffer

    err := cipherlock.Encrypt(&ciphertext, plaintext, password, nil)
    if err != nil {
        log.Fatal(err)
    }

    // --- Decrypt ---
    var decrypted bytes.Buffer
    err = cipherlock.Decrypt(&decrypted, &ciphertext, password)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(decrypted.String())
    // Output: Hello, cipherlock!
}
```

File-to-file:

```go
err := cipherlock.EncryptFile("document.pdf", "document.pdf.encrypted", password, nil)
if err != nil {
    log.Fatal(err)
}

_, err = cipherlock.DecryptFile("document.pdf.encrypted", "document.pdf.restored", password)
```

## Encryption basics

### Encrypt

`Encrypt` is the simplest entry point. It reads plaintext from an `io.Reader` and
writes ciphertext to an `io.Writer`.

```go
func Encrypt(dst io.Writer, src io.Reader, password []byte, config *Config) error
```

When `config` is nil, `DefaultConfig` is used. The function auto-selects the
output format:

- **v0x05** (streaming, cleartext metadata) -- when config has no `FileMeta`
- **v0x06** (streaming, encrypted metadata) -- when `config.FileMeta` is set
- **v0x07** (multi-recipient streaming) -- when `config` has the multi-key flag
- **v0x08** (asymmetric) -- when using `EncryptAsymmetric`

### Decrypt

`Decrypt` reads ciphertext from an `io.Reader` and writes plaintext to an
`io.Writer`. It auto-detects the format version from the header.

```go
func Decrypt(dst io.Writer, src io.Reader, password []byte) error
var DecryptWithMeta(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error)
```

`DecryptWithMeta` returns the embedded file metadata when present.

### File helpers

```go
func EncryptFile(source, dest string, password []byte, config *Config) error
func DecryptFile(source, dest string, password []byte) error
func DecryptFileWithMeta(source, dest string, password []byte) (*FileMeta, error)
```

These open files for you. If `dest` is empty, a default path is derived from
`source` (append `.encrypted` for encryption, strip the extension for decryption).

### Context support

```go
func DecryptWithMetaContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte) (*FileMeta, error)
```

Respects context cancellation during decryption. Useful for long-running or
interruptible operations.

## Configuration

### Config struct

```go
type Config struct {
    SaltLen     int       // Argon2id salt length in bytes (default 16)
    Time        uint32    // Argon2id time parameter (default 3)
    Memory      uint32    // Argon2id memory in KB (default 65536 = 64MB)
    Threads     uint8     // Argon2id parallelism (default 4)
    KeyLen      uint32    // Derived key length in bytes (default 32)
    Checksum    bool      // Embed SHA-256 checksum; verified on decrypt
    ChunkSize   int       // Plaintext chunk size in bytes (default 65536)
    FileMeta    *FileMeta // File metadata (name, size, modtime, expires)
    Compression bool      // Enable zstd compression before encryption
}
```

`DefaultConfig` provides sensible defaults aligned with OWASP Argon2id recommendations:

```go
var DefaultConfig = &Config{
    SaltLen:   16,
    Time:      3,
    Memory:    64 * 1024,   // 64 MB
    Threads:   4,
    KeyLen:    32,
    ChunkSize: 64 * 1024,
}
```

### ConfigBuilder (fluent API)

`ConfigBuilder` provides a chainable, discoverable way to construct configurations:

```go
config := cipherlock.NewConfigBuilder().
    WithMemory(128 * 1024).   // 128 MB
    WithTime(4).               // time=4
    WithCompression().
    WithChecksum().
    WithFileMeta(&cipherlock.FileMeta{
        Name:    "report.pdf",
        ModTime: time.Now(),
    }).
    MustBuild()
```

Available methods:

| Method | Default | Description |
|--------|---------|-------------|
| `WithSaltLen(n int)` | 16 | Salt length in bytes |
| `WithTime(t uint32)` | 3 | Argon2id time parameter |
| `WithMemory(memoryKB uint32)` | 65536 | Argon2id memory in KB |
| `WithThreads(t uint8)` | 4 | Argon2id parallelism |
| `WithKeyLen(k uint32)` | 32 | Derived key length in bytes |
| `WithChunkSize(n int)` | 65536 | Plaintext chunk size |
| `WithChecksum()` | false | Enable SHA-256 checksum |
| `WithCompression()` | false | Enable zstd compression |
| `WithFileMeta(meta *FileMeta)` | nil | Attach file metadata |
| `Build() (*Config, error)` | - | Validate and return config |
| `MustBuild() *Config` | - | Return config without validation |

Use `Build()` when you want validation errors surfaced; use `MustBuild()` when
you know the values are valid (e.g. after user input has been validated).

### ApplyProfile

```go
func (c *Config) ApplyProfile(p *Profile)
```

Merges a saved profile into the config. Only non-zero profile fields override
the config values.

### FileMeta

```go
type FileMeta struct {
    Name      string    // Original filename
    Size      int64     // File size in bytes
    ModTime   time.Time // Modification time
    ExpiresAt time.Time // Time-gate expiration (gate command)
}
```

When attached to a Config, the output format switches to v0x06 (encrypted
metadata) so the filename and size are not visible without the password.

## Streaming API

The streaming readers and writers wrap encryption/decryption in composable
`io.Reader` and `io.Writer` interfaces. The underlying operation runs in a
background goroutine; errors surface on the next Read/Write or Close call.

### Readers

```go
func NewEncryptReader(src io.Reader, password []byte, config *Config) *EncryptReader
func NewDecryptReader(src io.Reader, password []byte) *DecryptReader
```

Read from the returned reader to get the transformed data:

```go
// Encrypt: read plaintext from src, reader produces ciphertext
plaintext := bytes.NewReader([]byte("secret data"))
encReader := cipherlock.NewEncryptReader(plaintext, password, config)
defer encReader.Close()

// Post encrypted data directly
resp, err := http.Post("https://example.com/upload", "application/octet-stream", encReader)

// Or write to a file
io.Copy(outputFile, encReader)
```

```go
// Decrypt: read ciphertext from src, reader produces plaintext
resp, _ := http.Get("https://example.com/secret.cipherlock")
defer resp.Body.Close()

decReader := cipherlock.NewDecryptReader(resp.Body, password)
defer decReader.Close()

io.Copy(os.Stdout, decReader)
```

### Writers

```go
func NewEncryptWriter(dst io.Writer, password []byte, config *Config) io.WriteCloser
func NewDecryptWriter(dst io.Writer, password []byte) io.WriteCloser
```

Write to the returned writer to produce transformed data on dst:

```go
// Encrypt: write plaintext, ciphertext appears on dst
encWriter := cipherlock.NewEncryptWriter(outputFile, password, config)
io.Copy(encWriter, plaintextFile) // writes encrypted data to outputFile
encWriter.Close()
```

```go
// Decrypt: write ciphertext, plaintext appears on dst
var plaintext bytes.Buffer
decWriter := cipherlock.NewDecryptWriter(&plaintext, password)
io.Copy(decWriter, encryptedFile) // writes decrypted data to plaintext
decWriter.Close()
```

### When to use each

| Pattern | Use case |
|---------|----------|
| `Encrypt(dst, src, ...)` | Simple encrypt-in-full, both ends are under your control |
| `NewEncryptReader(src, ...)` | You have a plaintext source and need a reader that produces ciphertext |
| `NewEncryptWriter(dst, ...)` | You have an output stream and need a writer that encrypts what's written |
| `Decrypt(dst, src, ...)` | Simple decrypt-in-full |
| `NewDecryptReader(src, ...)` | You have a ciphertext source and need a reader that produces plaintext |
| `NewDecryptWriter(dst, ...)` | You have an output stream and need a writer that decrypts what's written |

The reader/writer wrappers are particularly useful when integrating with
libraries that consume or produce `io.Reader`/`io.Writer`, such as HTTP servers,
gzip compression, or archive libraries.

## Key management

### Generate a random password

```go
func GeneratePassword(n int) ([]byte, error)
```

Generates `n` cryptographically random bytes and returns them as a hex-encoded
ASCII string (length `2n`). Uses `crypto/rand` and zeroes the intermediate
buffer after encoding.

```go
pwd, err := cipherlock.GeneratePassword(32)
fmt.Println(string(pwd)) // 64 hex characters
```

### Load a public key

```go
func LoadPublicKey(path string) (*X25519Recipient, error)
```

Reads a base64-encoded X25519 public key file (as produced by `cipherlock dial`)
and returns a recipient for `EncryptAsymmetric`.

```go
recipient, err := cipherlock.LoadPublicKey("alice.pub")
if err != nil {
    log.Fatal(err)
}
err = cipherlock.EncryptAsymmetric(dst, src, []*cipherlock.X25519Recipient{recipient}, config)
```

### Load an identity (private key)

```go
func LoadIdentity(path string, passphrase []byte) (*X25519Identity, error)
```

Reads a private key and returns the corresponding identity for asymmetric
decryption. Supports two formats:

- **cipherlock armored identities** (`.identity` files from `cipherlock dial`)
- **Ed25519 SSH private keys** (e.g. `~/.ssh/id_ed25519`)

If passphrase-protected, provide the passphrase. Ed25519 SSH keys with a
passphrase require the caller to decrypt the PEM block first.

```go
identity, err := cipherlock.LoadIdentity("mykey.identity", passphrase)
if err != nil {
    log.Fatal(err)
}
_, err = cipherlock.DecryptAsymmetric(dst, src, identity)
```

### Compute a key fingerprint

```go
func Fingerprint(pubKey []byte) string
```

Computes the SHA-256 hash of a raw 32-byte X25519 public key and returns a
human-readable string in groups of 4 hex characters separated by spaces.

```go
fp := cipherlock.Fingerprint(identity.PublicKey)
fmt.Println(fp) // "A1B2 C3D4 E5F6 0718 091A 1B2C 3D4E 5F60 ..."
```

Use fingerprints for out-of-band verification over a separate channel
(e.g. a phone call or encrypted messaging app).

### Generate a key pair

```go
func GenerateX25519Keypair() (*X25519Identity, error)
```

Generates a new X25519 key pair from `crypto/rand`. The returned identity
contains both the private and public key.

```go
identity, err := cipherlock.GenerateX25519Keypair()
if err != nil {
    log.Fatal(err)
}
// identity.PrivateKey (32 bytes)
// identity.PublicKey (32 bytes)
```

### Create a recipient struct

```go
func NewX25519Recipient(pubKey []byte) (*X25519Recipient, error)
```

Wraps a 32-byte raw X25519 public key into a `*X25519Recipient`.

```go
recipient, err := cipherlock.NewX25519Recipient(pubBytes)
```

### Serialization

```go
func SerializeX25519Identity(identity *X25519Identity, passphrase []byte) ([]byte, error)
func DeserializeX25519Identity(data, passphrase []byte) (*X25519Identity, error)
```

Serializes an identity to a portable armored format (optionally encrypted with
a passphrase). `DeserializeX25519Identity` parses that format back.

```go
data, err := cipherlock.SerializeX25519Identity(identity, nil) // no passphrase
```

### SSH identity support

```go
func IdentityFromSSHPrivateKey(data []byte) (*X25519Identity, error)
```

Parses an Ed25519 SSH private key and returns the corresponding
`*X25519Identity`. This is used internally by `LoadIdentity` as the fast path
for Ed25519 keys without PEM passphrase protection.

## Asymmetric encryption

Encrypt to a public key, decrypt with the corresponding private key.

```go
func EncryptAsymmetric(dst io.Writer, src io.Reader, recipients []*X25519Recipient, config *Config) error
func DecryptAsymmetric(dst io.Writer, src io.Reader, identity *X25519Identity) error
func DecryptAsymmetricWithMeta(dst io.Writer, src io.Reader, identity *X25519Identity) (*FileMeta, error)
```

Uses ECDH + HKDF-SHA256 for key agreement. Each recipient gets an ephemeral
key that derives the same file key. Output format is v0x08.

```go
// Encrypt to one or more recipients
alice, _ := cipherlock.LoadPublicKey("alice.pub")
bob, _ := cipherlock.LoadPublicKey("bob.pub")

err := cipherlock.EncryptAsymmetric(dst, src,
    []*cipherlock.X25519Recipient{alice, bob},
    &cipherlock.Config{Compression: true})

// Decrypt
identity, _ := cipherlock.LoadIdentity("mykey.identity", passphrase)
plaintext, err := cipherlock.DecryptAsymmetric(dst, src, identity)
```

## Multi-recipient encryption

Encrypt once with multiple passwords so any one of them can decrypt.

```go
func EncryptStreamMulti(dst io.Writer, src io.Reader, passwords [][]byte, config *Config) error
func DecryptStreamMulti(dst io.Writer, src io.Reader, passwords [][]byte) (int, error)
```

Output format is v0x07. The file key is encrypted once per password, so each
recipient only needs to know their own password. The `DecryptStreamMulti`
function tries each password in order and returns the index that succeeded.

```go
pwds := [][]byte{[]byte("alice-password"), []byte("bob-password")}
err := cipherlock.EncryptStreamMulti(dst, src, pwds, nil)

// Decrypt: try passwords until one works
n, err := cipherlock.DecryptStreamMulti(dst, src, pwds)
// n == index of matching password
```

## Profiles

Save and reuse Argon2id parameter sets. Useful after running the `bench`
command to persist the optimal settings for your hardware.

```go
type Profile struct {
    Time        uint32 `json:"time"`
    Memory      uint32 `json:"memory"`
    Threads     uint8  `json:"threads"`
    Checksum    bool   `json:"checksum"`
    Compression bool   `json:"compression"`
}
```

### Profile functions

```go
func ProfilesPath() (string, error)                        // ~/.config/cipherlock/profiles.json
func LoadProfiles() (map[string]Profile, error)            // all saved profiles
func SaveProfiles(profiles map[string]Profile) error        // write atomically
```

`SaveProfiles` writes atomically via tempfile + rename, so concurrent readers
never see a partially-written file.

```go
profiles, err := cipherlock.LoadProfiles()
if err != nil {
    log.Fatal(err)
}
fmt.Println(profiles["my-machine"])
// {Time:4 Memory:131072 Threads:8 Checksum:false Compression:true}
```

## Format detection

```go
func IsEncrypted(path string) (bool, error)         // check a file by path
func IsEncryptedReader(r io.Reader) (bool, io.Reader, error)  // check a stream (binary magic)
func IsArmoredReader(r io.Reader) (bool, io.Reader, error)    // check a stream (ASCII-armor header)
```

`IsEncrypted` checks for the binary magic header (CV2\0) and, if that fails,
the ASCII-armor header (`-----BEGIN CIPHERLOCK-----`).

`IsEncryptedReader` checks a stream for the binary magic header. It returns a
new reader with the consumed bytes prepended -- always use the returned reader
for subsequent operations.

`IsArmoredReader` checks for the ASCII-armor header and returns a reconstructed
reader with the consumed prefix.

```go
// File check
ok, err := cipherlock.IsEncrypted(path)
if ok {
    _, err = cipherlock.DecryptFile(path, "output", password)
}

// Stream check
ok, r, err := cipherlock.IsEncryptedReader(input)
if ok {
    err = cipherlock.Decrypt(dst, r, password)
}
```

## Directory encryption

Encrypt or decrypt an entire directory (tar + gzip before encrypt).

```go
func EncryptDir(srcDir string, dst io.Writer, password []byte, config *Config) error
func DecryptDir(src io.Reader, destDir string, password []byte) error
```

The directory is packed into a tar.gz archive, then encrypted as a single
stream. On decrypt, the archive is extracted into the destination directory.

```go
// Encrypt
f, _ := os.Create("project.cipherlock")
err := cipherlock.EncryptDir("./my-project", f, password, nil)

// Decrypt
f, _ := os.Open("project.cipherlock")
err := cipherlock.DecryptDir(f, "./my-project-restored", password)
```

## Re-keying

Change a file's password without decrypting to disk (v0x07 only).

```go
func ReKey(src io.ReaderSeeker, oldPassword, newPassword []byte, config *Config) error
func ReKeyFile(path string, oldPassword, newPassword []byte, config *Config) error
```

The file key is decrypted with the old password, then re-encrypted with a
fresh salt derived from the new password. The ciphertext payload is untouched.

```go
err := cipherlock.ReKeyFile("secret.cipherlock", oldPwd, newPwd, nil)
```

A `Config` can be provided to change KDF parameters or enable compression
during re-keying.

## Metadata

Read file metadata without decrypting the entire stream.

```go
func ReadStreamMeta(src io.Reader) (*FileMeta, error)
func ReadStreamMetaWithPassword(src io.Reader, password []byte) (*FileMeta, error)
```

`ReadStreamMeta` works on formats with cleartext metadata (v0x05).
`ReadStreamMetaWithPassword` is required for formats with encrypted metadata
(v0x06/v0x07).

```go
meta, err := cipherlock.ReadStreamMetaWithPassword(reader, password)
if meta != nil {
    fmt.Println("Filename:", meta.Name)
    fmt.Println("Size:", meta.Size)
    fmt.Println("Expires:", meta.ExpiresAt)
}
```

## Error handling

### Sentinel errors

Use `errors.Is` / `errors.As` to check for specific error conditions:

```go
err := cipherlock.Decrypt(dst, src, password)
switch {
case errors.Is(err, cipherlock.ErrAuthFailed):
    // wrong password or corrupted data
case errors.Is(err, cipherlock.ErrCorrupted):
    // malformed or incomplete input
case errors.Is(err, cipherlock.ErrChecksumMismatch):
    // data integrity check failed
case errors.Is(err, cipherlock.ErrVersionMismatch):
    // format version not supported
case errors.Is(err, cipherlock.ErrInvalidFormat):
    // not a cipherlock file
case errors.Is(err, cipherlock.ErrEncryptedMeta):
    // metadata is encrypted; use ReadStreamMetaWithPassword
case errors.Is(err, cipherlock.ErrConfigInvalid):
    // Config.Validate() failed
case errors.Is(err, cipherlock.ErrIdentityNeedsPassphrase):
    // identity is passphrase-protected, provide one
case errors.Is(err, cipherlock.ErrUnsupportedIdentity):
    // identity type not recognized
case errors.Is(err, cipherlock.ErrAtLeastOnePassword):
    // empty password list in multi-recipient mode
}
```

### Edge cases

| Scenario | Behavior |
|----------|----------|
| Empty input | Encrypt produces valid ciphertext (empty stream). Decrypt returns empty output with no error. |
| Zero-byte password | Accepted by KDF (Argon2id accepts any length). Not recommended. |
| nil config | `DefaultConfig` is used. |
| Corrupted header | Returns `ErrCorrupted` during decrypt. |
| Truncated ciphertext | Returns `ErrCorrupted` or `ErrAuthFailed`. |
| Wrong password | Returns `ErrAuthFailed` (AES-GCM authentication fails). |

## Best practices

### Passwords

- Use `GeneratePassword(32)` or longer for machine-generated keys.
- Clear passwords after use: `cipherlock.Clear(slice)` or
  `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf.XOR` patterns.
- The library does NOT automatically clear your password slices after
  encryption/decryption. You own the memory.

### Argon2id tuning

- Use the `cipherlock bench` CLI command to find optimal parameters for your
  hardware, then save with `--save` and load via `LoadProfiles()`.
- On servers, lower memory (256-512 MB) and higher time (4-6) is often a
  better trade-off than extreme memory.
- On end-user devices, prefer higher memory (1-2 GB) with lower time (2-3).

### Streaming vs. in-memory

- For files up to ~100MB, the simple `Encrypt`/`Decrypt` functions (v0x02/v0x03)
  are fine. These load the entire plaintext into memory.
- For larger files or streams, use `EncryptStream`/`DecryptWithMeta` (v0x05+)
  which process in 64KB chunks with constant memory overhead.
- The streaming readers/writers (`NewEncryptReader`/`NewEncryptWriter`) use
  the streaming format internally.

### Thread safety

- `Config` values should not be modified concurrently during encryption.
- `EncryptStream`, `DecryptWithMeta`, and the streaming readers/writers are
  safe as long as each goroutine has its own `Config` and password slices.
- `ProfilesPath()`, `LoadProfiles()`, `SaveProfiles()` are safe.
- `SaveProfiles` uses atomic rename to prevent torn writes.

## Complete API reference

### Encrypt

| Function | Returns | Description |
|----------|---------|-------------|
| `Encrypt` | `error` | Reader-to-writer encrypt (auto-selects format) |
| `EncryptFile` | `error` | File-to-file encrypt |
| `EncryptStream` | `(int64, error)` | Reader-to-writer (v0x05+) |
| `EncryptStreamV2` | `(int64, error)` | Reader-to-writer (v0x06, encrypted metadata) |
| `EncryptStreamMulti` | `error` | Multi-password reader-to-writer (v0x07) |
| `EncryptDir` | `error` | Directory encrypt (tar.gz before encrypt) |
| `EncryptAsymmetric` | `error` | Public-key reader-to-writer (v0x08) |

### Decrypt

| Function | Returns | Description |
|----------|---------|-------------|
| `Decrypt` | `error` | Reader-to-writer decrypt (auto-detect format) |
| `DecryptFile` | `error` | File-to-file decrypt |
| `DecryptFileWithMeta` | `(*FileMeta, error)` | File-to-file with metadata |
| `DecryptWithMeta` | `(*FileMeta, error)` | Reader-to-writer with metadata |
| `DecryptWithMetaContext` | `(*FileMeta, error)` | Context-aware reader-to-writer |
| `DecryptDir` | `error` | Directory decrypt to disk |
| `DecryptAsymmetric` | `error` | Identity-based reader-to-writer decrypt |
| `DecryptAsymmetricWithMeta` | `(*FileMeta, error)` | Identity-based with metadata |

### Streaming wrappers

| Function | Returns | Description |
|----------|---------|-------------|
| `NewEncryptReader` | `*EncryptReader` | Read plaintext, get ciphertext |
| `NewDecryptReader` | `*DecryptReader` | Read ciphertext, get plaintext |
| `NewEncryptWriter` | `io.WriteCloser` | Write plaintext, ciphertext on dst |
| `NewDecryptWriter` | `io.WriteCloser` | Write ciphertext, plaintext on dst |

### Config

| Function / Type | Description |
|----------------|-------------|
| `Config` | Encryption parameter struct |
| `NewConfigBuilder()` | Fluent builder starting from defaults |
| `ConfigBuilder.With*` | Chainable field setters |
| `ConfigBuilder.Build()` | Validate and return `*Config` |
| `ConfigBuilder.MustBuild()` | Return without validation |
| `Config.Validate()` | Check all fields are in valid bounds |
| `Config.ApplyProfile(p)` | Merge profile values into config |
| `DefaultConfig` | OWASP-recommended defaults |
| `Profile` | Named Argon2id parameter set |
| `FileMeta` | File metadata (name, size, time, expires) |

### Profiles

| Function | Returns | Description |
|----------|---------|-------------|
| `ProfilesPath` | `(string, error)` | Path to profiles.json |
| `LoadProfiles` | `(map[string]Profile, error)` | Load all saved profiles |
| `SaveProfiles` | `error` | Atomically save profiles |

### Key helpers

| Function | Returns | Description |
|----------|---------|-------------|
| `GeneratePassword` | `([]byte, error)` | Generate random hex password |
| `Fingerprint` | `string` | SHA-256 fingerprint of public key |
| `LoadPublicKey` | `(*X25519Recipient, error)` | Load base64 public key file |
| `LoadIdentity` | `(*X25519Identity, error)` | Load private key (SSH or cipherlock) |
| `NewX25519Recipient` | `(*X25519Recipient, error)` | Wrap raw public key bytes |
| `GenerateX25519Keypair` | `(*X25519Identity, error)` | Generate new key pair |
| `SerializeX25519Identity` | `([]byte, error)` | Serialize identity to armored bytes |
| `DeserializeX25519Identity` | `(*X25519Identity, error)` | Parse armored identity bytes |
| `IdentityFromSSHPrivateKey` | `(*X25519Identity, error)` | Parse Ed25519 SSH private key |
| `Clear` | - | Zero a byte slice |

### Detection

| Function | Returns | Description |
|----------|---------|-------------|
| `IsEncrypted` | `(bool, error)` | Check file path for cipherlock magic |
| `IsEncryptedReader` | `(bool, io.Reader, error)` | Check reader for binary magic |
| `IsArmoredReader` | `(bool, io.Reader, error)` | Check reader for ASCII-armor header |
| `IsArmored` | `(bool, error)` | Check byte slice for armor header |

### Re-key / Formats

| Function / Type | Description |
|----------------|-------------|
| `ReKey` | Re-encrypt file key in a stream |
| `ReKeyFile` | Re-encrypt file key in place |
| `ReadStreamMeta` | Read cleartext metadata from stream |
| `ReadStreamMetaWithPassword` | Read encrypted metadata from stream |
| `Armor` | Encode bytes to ASCII-armor format |
| `UnarmorBytes` | Decode ASCII-armor bytes to binary |
