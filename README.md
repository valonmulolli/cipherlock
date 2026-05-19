# cipherlock

[![CI](https://github.com/valonmulolli/cipherlock/actions/workflows/ci.yml/badge.svg)](https://github.com/valonmulolli/cipherlock/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/valonmulolli/cipherlock.svg)](https://pkg.go.dev/github.com/valonmulolli/cipherlock)

AES-256-GCM file encryption with Argon2id key derivation.

cipherlock is a Go library and CLI tool for encrypting files and directories using authenticated encryption. It uses Argon2id (memory-hard key derivation) to resist GPU and ASIC brute-force attacks, and AES-256-GCM for verified confidentiality and integrity.

## Features

- **Strong encryption**: AES-256-GCM authenticated encryption with 12-byte random nonces.
- **Memory-hard KDF**: Argon2id key derivation with configurable time, memory, and parallelism parameters. Defaults follow OWASP recommendations (time=3, memory=64MB, threads=4).
- **Streaming encryption**: Reads and encrypts files in 64KB chunks. No upper file size limit — only the current chunk resides in memory.
- **Directory encryption**: Archive entire directories (tar + gzip) before encryption for atomic encrypted bundles.
- **Pipe mode**: Encrypt from stdin and write to stdout for seamless shell integration.
- **Password generation**: Generate cryptographically random passwords with `--gen-password`.
- **ASCII-armor output**: Base64 armored format for sharing encrypted files via text or email.
- **Key file support**: Read password from a file instead of interactive prompt.
- **Secure file shredding**: Overwrite original with random data before deletion on --in-place.
- **Shell completion**: Generate completion scripts for bash, zsh, fish, and powershell.
- **V1 backward compatibility**: Decrypt files created with the original PBKDF2+SHA1 format.
- **Progress indication**: Visual progress bar for large file operations.
- **Checksum verification**: Embedded SHA-256 checksum of plaintext. Verified automatically on decrypt when present.
- **Re-key files**: Change the password on an encrypted file without decrypting to disk.
- **Multi-recipient encryption**: Encrypt once for multiple passwords. Each recipient uses their own password to decrypt.
- **Library + CLI dual use**: Importable Go package with a full-featured command-line interface built with Cobra.
- **Password strength estimation**: Rates password entropy from "very weak" to "very strong" on encrypt/rekey.
- **Saved config profiles**: Store and reuse Argon2id parameter sets with `config set-profile` / `--profile`.
- **KDF progress indicator**: "Deriving key..." throbber and file-size progress bars during encrypt/decrypt.
- **Context-aware library API**: `EncryptContext`, `DecryptContext`, `EncryptStreamContext` — cancel long operations via Go contexts.
- **Sentinel error types**: `ErrAuthFailed`, `ErrChecksumMismatch`, `ErrCorrupted` — programmatic error handling instead of string matching.

## Usage

### Encrypt a file

    cipherlock encrypt document.pdf

Creates `document.pdf.encrypted` in the same directory.

### Decrypt a file

    cipherlock decrypt document.pdf.encrypted

Restores `document.pdf` if the password is correct.

### Encrypt in-place (overwrite source)

    cipherlock encrypt --in-place document.pdf

Encrypts the file and replaces the original. A temporary file is used so the original is only overwritten on successful encryption.

### Specify output path

    cipherlock encrypt document.pdf -o secret.enc
    cipherlock decrypt secret.enc -o document.pdf

### Encrypt a directory

    cipherlock encrypt ./projects/secrets/

Archives the directory (tar+gzip), encrypts it, and writes `secrets.cipherlock`.

### Decrypt a directory

    cipherlock decrypt secrets.cipherlock -o ./restored/

### Use pipe mode

    cat document.pdf | cipherlock encrypt > document.pdf.enc
    cat document.pdf.enc | cipherlock decrypt > document.pdf

### Generate a password

    cipherlock encrypt --gen-password document.pdf

Generates a 64-character hex-encoded random password and prints it to stderr. The password is shown only once during encryption.

### Armor mode (ASCII-armor output)

    cipherlock encrypt --armor document.pdf -o document.asc

Wraps the encrypted output in base64 with PEM-style headers. Suitable for sharing via email, chat, or other text-only channels.

    -----BEGIN CIPHERLOCK-----
    <base64-encoded data, wrapped at 64 characters>
    -----END CIPHERLOCK-----

Decrypt auto-detects the armor format -- no special flag required.

### Use a key file

    cipherlock encrypt --key-file ~/.keys/myapp.key document.pdf
    cipherlock decrypt --key-file ~/.keys/myapp.key document.pdf.encrypted

Reads the password from a file instead of prompting interactively. Useful for scripts and automation.

### Multi-recipient encryption

Encrypt a file for multiple recipients. Each recipient can decrypt with their own password:

    cipherlock encrypt --recipient "alice" --recipient "bob" document.pdf

The primary password is prompted interactively (or provided via `--key-file` or `--gen-password`). Additional recipients are added with `--recipient`. All recipients can independently decrypt the file.

### Re-key an encrypted file

Change the password on an encrypted file without decrypting to disk:

    cipherlock rekey document.pdf.encrypted

Prompts for the old and new passwords. Supports `--key-file`, `--new-key-file`, `--output`, and `--in-place` flags.

### Verify checksum

Encrypt with an embedded SHA-256 checksum:

    cipherlock encrypt --checksum document.pdf

On decrypt, the checksum is automatically verified if present:

    cipherlock decrypt document.pdf.encrypted

If the file was tampered with, decrypt reports a checksum mismatch error.

### Config profiles

Save Argon2id parameter sets for reuse:

    cipherlock config set-profile high --time 4 --memory 262144 --threads 8 --checksum
    cipherlock encrypt --profile high document.pdf

List and remove profiles:

    cipherlock config list-profiles
    cipherlock config remove-profile high

Profiles are stored at `~/.config/cipherlock/profiles.json`.

### Shell completion

    cipherlock completion bash > /etc/bash_completion.d/cipherlock
    cipherlock completion zsh > "${fpath[1]}/_cipherlock"
    cipherlock completion fish > ~/.config/fish/completions/cipherlock.fish

Supports bash, zsh, fish, and powershell. Requires no additional dependencies -- generated by cobra's built-in completion engine.

### Legacy format support

Files encrypted with the original `file-encryption` tool (PBKDF2+SHA1, 4096 iterations) can be decrypted using the same `decrypt` command. cipherlock detects the format automatically.

## Library usage

Import cipherlock in your Go project:

    import "github.com/valonmulolli/cipherlock/cipherlock"

### Encrypt data

```go
var buf bytes.Buffer
err := cipherlock.Encrypt(&buf, someReader, password, nil)
```

`Encrypt` now produces the v0x05 streaming format (same as `EncryptStream`). It reads the input in chunks and writes encrypted output incrementally. The entire file is never loaded into memory. For explicit streaming, use `EncryptStream`.

### Encrypt with metadata (filename, size, modtime)

Metadata is automatically collected from the source file when using the CLI and stored in the v0x05 header:

    cipherlock encrypt document.pdf

On decrypt without `--output`, the original filename, size, and modification time are restored automatically.

### Decrypt data

```go
var buf bytes.Buffer
err := cipherlock.Decrypt(&buf, someReader, password)
```

`Decrypt` auto-detects all format versions (v0x02, v0x03, v0x04, v0x05) — no special flag needed.

### Context-aware encryption (cancellable)

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

var buf bytes.Buffer
err := cipherlock.EncryptContext(ctx, &buf, someReader, password, nil)
// returns context.DeadlineExceeded if KDF or encryption takes too long
```

Available context variants: `EncryptContext`, `DecryptContext`, `EncryptStreamContext`, `DecryptStreamContext`, `EncryptMultiContext`.

### Error handling with sentinel errors

```go
if errors.Is(err, cipherlock.ErrAuthFailed) {
    // wrong password or corrupted data
}
if errors.Is(err, cipherlock.ErrChecksumMismatch) {
    // file was tampered with
}
if errors.Is(err, cipherlock.ErrCorrupted) {
    // file format is damaged
}
if errors.Is(err, cipherlock.ErrInvalidFormat) {
    // not a cipherlock file
}
```

Available sentinel errors: `ErrInvalidFormat`, `ErrVersionMismatch`, `ErrAuthFailed`, `ErrChecksumMismatch`, `ErrCorrupted`, `ErrAtLeastOnePassword`.

### Read file metadata without decrypting

```go
meta, err := cipherlock.ReadStreamMeta(encryptedFile)
// meta.Name, meta.Size, meta.ModTime (nil if not a v0x05 stream)
```

### Encrypt a file (using EncryptFile)

```go
err := cipherlock.EncryptFile("source.txt", "source.txt.encrypted", password, nil)
```

### Decrypt a file

```go
err := cipherlock.DecryptFile("source.txt.encrypted", "source.txt", password)
```

### Encrypt a directory

```go
err := cipherlock.EncryptDir("./mydir", "mydir.cipherlock", password, nil)
```

### Decrypt a directory

```go
err := cipherlock.DecryptDir("mydir.cipherlock", "./mydir", password)
```

### Custom configuration

```go
config := &cipherlock.Config{
    SaltLen: 16,
    Time:    4,
    Memory:  128 * 1024, // 128 MB
    Threads: 8,
    KeyLen:  32,
}
err := cipherlock.Encrypt(dst, src, password, config)
```

Setting `nil` uses `cipherlock.DefaultConfig` (time=3, memory=64MB, threads=4).

### Check if a file is encrypted

```go
ok, err := cipherlock.IsEncrypted("file.enc")
```

### Encrypt with ASCII armor

```go
var encrypted bytes.Buffer
cipherlock.Encrypt(&encrypted, someReader, password, nil)
var armored bytes.Buffer
cipherlock.Armor(&armored, encrypted.Bytes())
```

### Decrypt armored data

```go
data, _ := cipherlock.UnarmorBytes(armoredData)
var plaintext bytes.Buffer
cipherlock.Decrypt(&plaintext, bytes.NewReader(data), password)
```

### Check if data is armored

```go
if cipherlock.IsArmored(data) {
    // handle armored format
}
```

### Securely delete a file

```go
err := cipherlock.Shred("sensitive-file.txt")
```

Overwrites the file with random data, then zeros, then removes it.

### Decrypt legacy V1 format

```go
err := cipherlock.DecryptFileV1("old_file.encrypted", "old_file", password)
```

### Re-key an encrypted file

```go
err := cipherlock.ReKeyFile("old.encrypted", "new.encrypted", oldPassword, newPassword, nil)
```

### Multi-recipient encryption

```go
passwords := [][]byte{[]byte("alice"), []byte("bob"), []byte("charlie")}
var buf bytes.Buffer
err := cipherlock.EncryptMulti(&buf, someReader, passwords, nil)

var decBuf bytes.Buffer
err := cipherlock.Decrypt(&decBuf, bytes.NewReader(buf.Bytes()), []byte("bob"))
```

## File format

cipherlock uses a self-describing binary format with versioned headers:

### V2/V3 (single-recipient)

    4 bytes    Magic: "CV2\0"
    1 byte     Version: 0x02 or 0x03
    1 byte     Flags (v0x03 only): bit 0 = checksum present
    2 bytes    Salt length (little-endian)
    N bytes    Argon2id salt
    4 bytes    Argon2 time parameter (little-endian)
    4 bytes    Argon2 memory parameter (little-endian)
    1 byte     Argon2 threads parameter
    4 bytes    Key length (little-endian)
    12 bytes   AES-GCM nonce
    [32 bytes  SHA-256 checksum (v0x03 only, present when flags bit 0 set)]
    Variable   Ciphertext + GCM authentication tag (last 16 bytes)

### V4 (multi-recipient)

    4 bytes    Magic: "CV2\0"
    1 byte     Version: 0x04
    1 byte     Flags: bit 0 = checksum present
    4 bytes    Number of recipients (little-endian)
    For each recipient:
      2 bytes  Salt length (little-endian)
      N bytes  Argon2id salt
      4 bytes  Time parameter (little-endian)
      4 bytes  Memory parameter (little-endian)
      1 byte   Threads
      4 bytes  Key length (little-endian)
      12 bytes Nonce for key encryption
      2 bytes  Sealed key length (little-endian)
      M bytes  Encrypted file key + GCM tag
    12 bytes   File nonce
    [32 bytes  SHA-256 checksum (when flags bit 0 set)]
    Variable   Ciphertext + GCM authentication tag (last 16 bytes)

The ciphertext is encrypted with a random file key, which is then encrypted once per recipient. Each recipient independently derives their own key with Argon2id to decrypt the file key.

### V5 (streaming)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x05
     1 byte     Flags: bit 0 = checksum present
     2 bytes    Salt length (little-endian)
     N bytes    Argon2id salt
     4 bytes    Time parameter (little-endian)
     4 bytes    Memory parameter (little-endian)
     1 byte     Threads
     4 bytes    Key length (little-endian)
     4 bytes    Chunk size (plaintext bytes per chunk)
     1 byte     Has metadata (0 = no, 1 = yes)
     [If has metadata:]
       2 bytes  Filename length (little-endian)
       M bytes  Filename (UTF-8)
       8 bytes  File size (little-endian)
       8 bytes  Modification time (Unix nanosecond, little-endian)
     [32 bytes  SHA-256 checksum (trailer, when flags bit 0 set)]

     Zero or more data chunks:
       12 bytes  Nonce
       4 bytes   Ciphertext + GCM tag length (little-endian, 0 = end of stream)
       N bytes   Ciphertext + 16-byte GCM tag

     End of stream: 4 zero bytes in place of ciphertext length

The streaming format encrypts data incrementally in fixed-size chunks. Only one chunk is held in memory at a time. Each chunk uses a unique random nonce and is independently authenticated. The checksum (when enabled) is computed incrementally and stored as a trailer.

Metadata (filename, size, modtime) is stored in the cleartext header for zero-cost inspection without decryption. This means anyone with access to the encrypted file can see the original filename and size. A future format version may encrypt the header.

### ASCII-armor format

When using `--armor`, the binary format above is wrapped in base64 encoding with PEM-style delimiters:

    -----BEGIN CIPHERLOCK-----
    <base64-encoded ciphertext, wrapped at 64 columns>
    -----END CIPHERLOCK-----

The armored format is self-identifying -- decrypt detects it automatically by reading the header line.

## Security

### Key derivation

cipherlock uses Argon2id, the current state of the art in password-based key derivation. It is memory-hard, meaning an attacker needs a proportionally large amount of memory to attempt each password guess, making GPU and ASIC acceleration impractical.

Default parameters (time=3, memory=64MB, threads=4) follow the OWASP Password Storage Cheat Sheet recommendations for 2024+. For higher security environments, increase the Memory parameter to 128MB or 256MB.

### Authenticated encryption

AES-256-GCM provides both confidentiality and integrity. Any tampering with the ciphertext is detected during decryption, and the operation fails with an authentication error before any data is written.

### Nonce generation

A fresh 12-byte random nonce is generated for every encryption operation using `crypto/rand`. Nonces never repeat with overwhelming probability.

### Safe file operations

When using `--in-place`, cipherlock writes to a temporary file first. Only after a successful encryption does it atomically replace the original. A failed operation never destroys the source data.

After successful replacement, the original file is securely shredded (overwritten with random data, then zeros, then removed) to prevent recovery of the plaintext from disk blocks.

### V1 format caveat

The original file-encryption tool used PBKDF2 with only 4096 iterations and SHA-1. Files created with that tool remain decryptable via cipherlock, but re-encrypt them with the V2 format to get Argon2id protection.

## Installation

### Via Go install

    go install github.com/valonmulolli/cipherlock@latest

### From source

    git clone https://github.com/valonmulolli/cipherlock.git
    cd cipherlock
    go build -o cipherlock .

### Prebuilt binaries

Download the latest release for your platform from the [releases page](https://github.com/valonmulolli/cipherlock/releases). Binaries are available for Linux, macOS, and Windows (amd64 and arm64).

## Development

    git clone https://github.com/valonmulolli/cipherlock.git
    cd cipherlock
    go test ./...

## License

MIT
