# cipherlock

AES-256-GCM file encryption with Argon2id key derivation.

cipherlock is a Go library and CLI tool for encrypting files and directories using authenticated encryption. It uses Argon2id (memory-hard key derivation) to resist GPU and ASIC brute-force attacks, and AES-256-GCM for verified confidentiality and integrity.

## Features

- **Strong encryption**: AES-256-GCM authenticated encryption with 12-byte random nonces.
- **Memory-hard KDF**: Argon2id key derivation with configurable time, memory, and parallelism parameters. Defaults follow OWASP recommendations (time=3, memory=64MB, threads=4).
- **Streaming API**: Encrypt and decrypt arbitrary data streams via `io.Reader` and `io.Writer` interfaces.
- **Directory encryption**: Archive entire directories (tar + gzip) before encryption for atomic encrypted bundles.
- **Pipe mode**: Encrypt from stdin and write to stdout for seamless shell integration.
- **Password generation**: Generate cryptographically random passwords with `--gen-password`.
- **V1 backward compatibility**: Decrypt files created with the original PBKDF2+SHA1 format.
- **Progress indication**: Visual progress bar for large file operations.
- **Library + CLI dual use**: Importable Go package with a full-featured command-line interface built with Cobra.

## Installation

### Via Go install

    go install github.com/valonmulolli/cipherlock@latest

### From source

    git clone https://github.com/valonmulolli/cipherlock.git
    cd cipherlock
    go build -o cipherlock .

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

### Decrypt data

```go
var buf bytes.Buffer
err := cipherlock.Decrypt(&buf, someReader, password)
```

### Encrypt a file

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

### Decrypt legacy V1 format

```go
err := cipherlock.DecryptFileV1("old_file.encrypted", "old_file", password)
```

## File format

cipherlock uses a self-describing binary format:

    4 bytes    Magic: "CV2\0"
    1 byte     Version: 0x02
    2 bytes    Salt length (little-endian)
    N bytes    Argon2id salt
    4 bytes    Argon2 time parameter (little-endian)
    4 bytes    Argon2 memory parameter (little-endian)
    1 byte     Argon2 threads parameter
    4 bytes    Key length (little-endian)
    12 bytes   AES-GCM nonce
    Variable   Ciphertext + GCM authentication tag (last 16 bytes)

This header enables full parameter recovery during decryption without external configuration.

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

### V1 format caveat

The original file-encryption tool used PBKDF2 with only 4096 iterations and SHA-1. Files created with that tool remain decryptable via cipherlock, but re-encrypt them with the V2 format to get Argon2id protection.

## Development

    git clone https://github.com/valonmulolli/cipherlock.git
    cd cipherlock
    go test ./...

## License

MIT
