## cipherlock decrypt

Decrypt a file

### Synopsis

Decrypt one or more files previously encrypted with cipherlock.

Supports both the current V2 format (Argon2id) and the legacy
V1 format (PBKDF2+SHA1) for backward compatibility.

If no output path is specified, the decrypted output strips the
.encrypted or .cipherlock extension, or appends .decrypted.
Use --out-dir to write all outputs to a specific directory.

When <path> is "-", read encrypted data from stdin and write
plaintext to stdout.

```
cipherlock decrypt [flags] <path> [<path>...]
```

### Options

```
      --check                    verify password and format without writing output
      --dir                      decrypt directory archive and extract
      --force                    overwrite existing output files without prompting
  -h, --help                     help for decrypt
      --identity string          path to X25519 identity (private key) file for asymmetric decryption
  -j, --jobs int                 number of parallel workers (default: sequential)
      --key-file string          read password from file instead of prompting
      --keychain                 read password from system keychain
      --out-dir string           output directory for batch decryption
  -o, --output string            output file path
      --passphrase-file string   read identity passphrase from file instead of prompting
      --password-env string      read password from environment variable
      --password-fd string       read password from file descriptor number (e.g. 0 for stdin pipe)
      --password-stdin           read password from stdin
      --save-keychain            save password to system keychain after decryption
      --ssh-privkey string       path to Ed25519 SSH private key for asymmetric decryption
```

### Options inherited from parent commands

```
      --backup           save original with .bak extension before overwriting
      --color1 string    color for errors (default "#e3342f")
      --color2 string    color for text/labels (default "#22808c")
      --color3 string    color for spinner chars (default "#ffffff")
      --color4 string    color for filled bar (default "#32b8c6")
      --color5 string    color for empty bar (default "#d6d5d4")
      --color6 string    color for gradient B (default "#0f3639")
      --dry-run          simulate the operation without writing any files
      --exclude string   exclude files matching this glob pattern
      --in-place         overwrite the source file instead of creating a new one
      --include string   only process files matching this glob pattern
      --keep             keep the original file (opposite of --in-place)
      --no-color         disable ANSI color output
      --quiet            suppress progress output
      --recursive        process directories recursively
```

### SEE ALSO

* [cipherlock](cipherlock.md)	 - AES-256-GCM file encryption with Argon2id key derivation

