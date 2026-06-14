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
- **Context-aware library API**: `EncryptContext`, `DecryptContext`, `DecryptWithMetaContext`, `EncryptStreamContext` — cancel long operations via Go contexts.
- **Sentinel error types**: `ErrAuthFailed`, `ErrChecksumMismatch`, `ErrCorrupted` — programmatic error handling instead of string matching.
- **Encrypted-metadata streaming (v0x06)**: Optional `FileMeta` is stored as an encrypted chunk so the original filename and size are not visible without the password.
- **Streaming multi-recipient (v0x07)**: Multi-recipient encryption that streams the plaintext in fixed-size chunks. No upper file size limit, even with `--recipient` flags.
- **Defensive header bounds**: Salt, key length, chunk size, and recipient count are validated against strict upper limits to prevent OOM via maliciously crafted files.

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

To recover metadata alongside decryption:

```go
var buf bytes.Buffer
meta, err := cipherlock.DecryptWithMetaContext(ctx, &buf, someReader, password)
// meta is non-nil for v0x06/v0x07 sources with attached FileMeta
```

Available context variants: `EncryptContext`, `DecryptContext`, `DecryptWithMetaContext`, `EncryptStreamContext`, `DecryptStreamContext`, `EncryptMultiContext`, `EncryptStreamV2Context`, `DecryptStreamV2Context`, `EncryptStreamMultiContext`, `DecryptStreamMultiContext`.

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
if errors.Is(err, cipherlock.ErrEncryptedMeta) {
    // metadata is encrypted; call ReadStreamMetaWithPassword with a password
}
```

Available sentinel errors: `ErrInvalidFormat`, `ErrVersionMismatch`, `ErrAuthFailed`, `ErrChecksumMismatch`, `ErrCorrupted`, `ErrAtLeastOnePassword`, `ErrEncryptedMeta`, `ErrNotArmored`.

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

Use `EncryptStreamMulti` (v0x07) for new code. It streams the plaintext
through encryption, supports an optional encrypted `FileMeta`, and is
the recommended path for arbitrarily large files.

```go
passwords := [][]byte{[]byte("alice"), []byte("bob"), []byte("charlie")}
var buf bytes.Buffer
err := cipherlock.EncryptStreamMulti(&buf, someReader, passwords, nil)

var decBuf bytes.Buffer
meta, err := cipherlock.DecryptStreamMultiFromReader(&decBuf, bytes.NewReader(buf.Bytes()), []byte("bob"))
// meta is non-nil when the source was encrypted with a FileMeta attached.
```

`EncryptMulti` (v0x04) is deprecated: it buffers the full plaintext in
memory. Existing v0x04 files are still readable, but new code should
target v0x07 via `EncryptStreamMulti`.

#### Recovering FileMeta on decrypt

The metadata-aware helpers return the `*FileMeta` attached at encrypt
time, which is non-nil only for v0x06/v0x07 sources:

```go
meta, err := cipherlock.DecryptWithMeta(dst, src, password)        // all formats
meta, err := cipherlock.DecryptFileWithMeta("file.enc", "out", pwd) // file variant
meta, err := cipherlock.DecryptStreamMultiFromReader(dst, src, pwd) // v0x07 only
```

For v0x02-v0x05 sources the returned meta is nil. Use
`ReadStreamMeta` / `ReadStreamMetaWithPassword` for streaming inspection
of the header without performing a full decrypt.

### Encrypted-metadata streaming (v0x06)

When you need to keep the original filename and size confidential, use the v0x06
format. The metadata is stored as an encrypted chunk so it is not visible in the
file without the password.

```go
cfg := &cipherlock.Config{
    SaltLen:   16,
    Time:      3,
    Memory:    64 * 1024,
    Threads:   4,
    KeyLen:    32,
    ChunkSize: 64 * 1024,
    FileMeta: &cipherlock.FileMeta{
        Name:    "secret-document.bin",
        Size:    1024,
        ModTime: time.Now(),
    },
}

var buf bytes.Buffer
if err := cipherlock.EncryptStreamV2(&buf, src, password, cfg); err != nil {
    return err
}

// Decrypting recovers the metadata:
var dec bytes.Buffer
meta, err := cipherlock.DecryptStreamV2(&dec, &buf, password)
// meta.Name == "secret-document.bin", meta.Size == 1024, etc.
```

Use `cipherlock.ReadStreamMetaWithPassword(r, password)` to read just the
metadata without streaming the rest of the file. For v0x05 files the password
is unused and the cleartext metadata is returned; for v0x06/v0x07 the password
and KDF are required to unseal the metadata chunk.

`ReadStreamMeta` (no password) still works for v0x05 files; for v0x06/v0x07
files it returns `cipherlock.ErrEncryptedMeta`.

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
     1 byte     Threads parameter
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

Metadata (filename, size, modtime) is stored in the cleartext header for zero-cost inspection without decryption. This means anyone with access to the encrypted file can see the original filename and size. To keep this metadata confidential, use v0x06 instead.

### V6 (streaming, encrypted metadata)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x06
     1 byte     Flags: bit 0 = checksum present, bit 1 = has metadata
     2 bytes    Salt length
     N bytes    Argon2id salt
     4 bytes    Time
     4 bytes    Memory
     1 byte     Threads
     4 bytes    Key length
     4 bytes    Chunk size

     [Optional encrypted metadata chunk, when flags bit 1 is set:]
       12 bytes  Nonce
       4 bytes   Ciphertext + GCM tag length
       M bytes   Ciphertext + 16-byte GCM tag (decrypts to: filenameLen(2) + name + size(8) + modtime(8))

     Zero or more data chunks: same as v0x05

     End of stream: 4 zero bytes
     [Optional 32-byte SHA-256 checksum trailer, when flags bit 0 is set]

Identical to v0x05 except the optional metadata is encrypted under the same key as the data, so the original filename and size are not visible without the password. Use `EncryptStreamV2` / `DecryptStreamV2` from the library, or the `cipherlock` CLI which auto-selects this format when the source has metadata.

### V7 (streaming, multi-recipient)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x07
     1 byte     Flags: bit 0 = checksum present, bit 1 = has metadata
     4 bytes    Number of recipients (little-endian)
     For each recipient:
       2 bytes  Salt length
       N bytes  Argon2id salt
       4 bytes  Time
       4 bytes  Memory
       1 byte   Threads
       4 bytes  Key length
       12 bytes Nonce for key encryption
       2 bytes  Sealed key length
       M bytes  Encrypted file key + GCM tag

     [Optional encrypted metadata chunk, when flags bit 1 is set:]
       12 bytes  Nonce
       4 bytes   Ciphertext length
       M bytes   Encrypted metadata (filename + size + modtime)

     Zero or more data chunks: each chunk is encrypted with the shared file key
       12 bytes  Nonce
       4 bytes   Ciphertext length (0 = end)
       N bytes   Ciphertext + 16-byte GCM tag

     End of stream: 4 zero bytes
     [Optional 32-byte SHA-256 checksum trailer, when flags bit 0 is set]

A fresh random file key encrypts the data (and optional metadata chunk). The file key is then sealed once per recipient using their derived key. This is the streaming replacement for the legacy v0x04 `EncryptMulti` and supports arbitrarily large files without buffering the plaintext. Use `EncryptStreamMulti` / `DecryptStreamMulti` from the library, or the `cipherlock` CLI which auto-selects this format when `--recipient` is given more than once.

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

## Threat model

cipherlock is designed to protect files at rest against an attacker who obtains
a copy of the encrypted file but does not know the password. The threat model
covers what cipherlock does, what it does not do, and the format-version
trade-offs.

### In scope

- **Confidentiality against offline brute force.** Argon2id with default
  parameters is memory-hard, raising the cost of each guess to the point where
  GPU and ASIC attacks are uneconomical. Use a high-entropy password; a
  short password is vulnerable regardless of KDF cost.
- **Integrity and authenticity.** Every chunk is independently authenticated
  with AES-256-GCM. Any bit flip, truncation, or chunk swap is detected before
  any plaintext is written. The optional SHA-256 trailer detects bit-level
  tampering at the plaintext level when enabled.
- **Metadata confidentiality (v0x06 / v0x07).** The original filename, size,
  and modification time are stored as an encrypted chunk in v0x06 and v0x07.
  Without the password, an attacker cannot tell whether the file is, say, a
  4 KiB text file or a 4 GiB video.
- **Memory exhaustion via malicious input.** Salt length, key length, chunk
  size, recipient count, and per-chunk ciphertext length are all bounded
  before allocation. A malicious file cannot cause multi-gigabyte allocations.
- **Atomic file replacement.** The `--in-place` CLI path writes to a
  temporary file and only renames it into place after successful encryption.
  The original is then shredded, so a crash mid-operation never destroys
  the source data.

### Out of scope

- **Online attacks.** cipherlock does not throttle password attempts; if an
  attacker can submit guesses to your decrypt endpoint, rate-limit at the
  application layer.
- **Side channels.** The library is not constant-time with respect to
  password length, chunk contents, or decryption outcomes. It is suitable
  for at-rest encryption, not for adversarial on-device use.
- **Live system threats.** cipherlock does not protect against a keylogger
  on the encrypting or decrypting machine, an OS-level memory dump, or a
  running process that reads the plaintext. Use a trusted, isolated
  environment for sensitive operations.
- **Traffic analysis.** The file size after encryption is approximately
  `plaintext_size + chunk_overhead`. For a v0x07 multi-recipient file the
  size grows linearly with the number of recipients. An attacker who
  observes the network sees file size and timing, not contents.
- **V1 / PBKDF2+SHA-1 files.** The V1 decrypt path exists for backward
  compatibility only. Re-encrypt with V2 or later to get Argon2id protection.

### Format-version trade-offs

| Version | Year | Use when                                                                | Avoid when                             |
| ------- | ---- | ----------------------------------------------------------------------- | -------------------------------------- |
| V2/V3   | 2024 | Single recipient, plaintext fits in memory, checksum not needed         | Files larger than a few hundred MB     |
| V4      | 2024 | Multi-recipient where all recipients can be enumerated at encrypt time  | Files larger than available RAM        |
| V5      | 2024 | Single recipient, streaming, large files; metadata can be public        | Filename/size are sensitive            |
| V6      | 2026 | Single recipient, streaming, large files, metadata must be confidential | You need zero-cost metadata inspection |
| V7      | 2026 | Multi-recipient, streaming, large files, metadata must be confidential  | Legacy interop with V4 is required     |

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
