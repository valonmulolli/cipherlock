# cipherlock

[![CI](https://github.com/valonmulolli/cipherlock/actions/workflows/ci.yml/badge.svg)](https://github.com/valonmulolli/cipherlock/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/valonmulolli/cipherlock.svg)](https://pkg.go.dev/github.com/valonmulolli/cipherlock)
[![Go Version](https://img.shields.io/github/go-mod/go-version/valonmulolli/cipherlock)](https://go.dev/dl/)
[![License](https://img.shields.io/github/license/valonmulolli/cipherlock)](LICENSE)
[![Security](https://img.shields.io/badge/security-threat%20model-informational)](SECURITY.md)

AES-256-GCM file encryption with Argon2id key derivation -- Go library and CLI tool.

## Features

- **AES-256-GCM** authenticated encryption with 12-byte random nonces
- **Argon2id** memory-hard KDF (default: time=3, memory=64MB, threads=4, OWASP-recommended)
- **zstd compression** (`--compress`): compress plaintext before encryption, auto-detected on decrypt
- **Streaming encryption**: reads and encrypts in 64KB chunks, no upper file size limit
- **Directory encryption**: tar + gzip before encrypt, decrypt with `--dir`
- **Pipe mode**: encrypt from stdin / decrypt to stdout for shell pipelines
- **Multi-recipient**: encrypt once for multiple passwords (v0x07)
- **Asymmetric X25519**: encrypt to public keys, decrypt with identity (v0x08)
- **Time-gated encryption** (`gate`): embeds an expiration time, decryption fails after expiry
- **Re-key** (`rotor`): change a file's password without decrypting to disk
- **Key fingerprinting**: `key fingerprint <pubkey>` displays SHA-256 hash for out-of-band verification
- **Auto-tuning benchmark** (`bench`): finds strongest Argon2id parameters for your hardware
- **ASCII-armor output**: base64 with PEM-style headers for text-only channels
- **Checksum verification**: embedded SHA-256, verified on decrypt when present
- **Secure shredding**: overwrite with random data + zeros before deletion
- **Config profiles**: save and reuse Argon2id parameter sets
- **Shell completion**: bash, zsh, fish, powershell
- **Backward compatible**: decrypts V1 PBKDF2+SHA1 format
- **Library + CLI dual use**: importable Go package with cobra CLI

[Threat model & cryptographic design](SECURITY.md) · [CLI reference](docs/cli/cipherlock.md)

## Quick start

    go install github.com/valonmulolli/cipherlock@latest

Encrypt a file:

    cipherlock encrypt document.pdf

Decrypt:

    cipherlock decrypt document.pdf.encrypted

Encrypt with compression:

    cipherlock encrypt --compress document.pdf

Re-encrypt with a new password:

    cipherlock rotor document.pdf.encrypted

Encrypt a directory:

    cipherlock encrypt ./projects/secrets/

Benchmark KDF parameters:

    cipherlock bench --save my-profile
    cipherlock encrypt --profile my-profile document.pdf

Generate a key pair and fingerprint:

    cipherlock dial mykey
    cipherlock key fingerprint mykey.pub

Encrypt with a public key:

    cipherlock encrypt --recipient-pubkey mykey.pub secret.txt

Full CLI command reference (all commands, flags, examples):

  - [CLI reference](docs/cli/cipherlock.md) -- auto-generated from cobra command definitions
  - `cipherlock <command> --help` -- built-in help for every command

## Library

    import "github.com/valonmulolli/cipherlock/cipherlock"

```go
// Encrypt a reader to a writer
var buf bytes.Buffer
err := cipherlock.Encrypt(&buf, someReader, password, nil)

// Decrypt a reader to a writer
var plain bytes.Buffer
err := cipherlock.Decrypt(&plain, someReader, password)

// Use the full streaming API with context support
meta, err := cipherlock.DecryptWithMetaContext(ctx, &plain, encryptedReader, password)

// Encrypt with custom configuration (compression, KDF params, metadata)
config := &cipherlock.Config{
    Memory: 128 * 1024,
    Compression: true,
    FileMeta: &cipherlock.FileMeta{Name: "doc.pdf"},
}
err := cipherlock.Encrypt(dst, src, password, config)
```

Full library documentation at [pkg.go.dev](https://pkg.go.dev/github.com/valonmulolli/cipherlock/cipherlock)
and [docs/lib/library.md](docs/lib/library.md).

## File format

Self-describing binary format with versioned headers (v0x02-v0x08). Wire-level
specifications are documented in the [package documentation](https://pkg.go.dev/github.com/valonmulolli/cipherlock/cipherlock).

## Security

Threat model, cryptographic design, defensive bounds, key memory zeroing, and
responsible disclosure process are documented in [SECURITY.md](SECURITY.md).

## Installation

    go install github.com/valonmulolli/cipherlock@latest

Or download prebuilt binaries from the [releases page](https://github.com/valonmulolli/cipherlock/releases)
(Linux, macOS, Windows; amd64 and arm64). Release archives include the binary,
LICENSE, README, [SECURITY.md](SECURITY.md), and [CLI docs](docs/cli/).
and [CLI docs](docs/cli/).

## Development

    git clone https://github.com/valonmulolli/cipherlock.git
    cd cipherlock
    go test ./...

Regenerate CLI documentation after changing commands or flags:

    go run tools/gendocs/main.go

## License

MIT
