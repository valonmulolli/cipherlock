## cipherlock bombe

Verify file integrity

### Synopsis

Verify that an encrypted file has not been tampered with.

Decrypts the file in memory and verifies the embedded checksum
without writing any output. Returns exit code 0 if the file is
intact and the password is correct, or a non-zero exit code if
the file has been corrupted or the password is wrong.

```
cipherlock bombe [flags] <file>
```

### Options

```
  -h, --help                  help for bombe
      --keychain              read password from system keychain
      --password-env string   read password from environment variable
      --password-fd string    read password from file descriptor number (e.g. 0 for stdin pipe)
      --password-stdin        read password from stdin
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
      --quiet            suppress progress output
      --recursive        process directories recursively
```

### SEE ALSO

* [cipherlock](cipherlock.md)	 - AES-256-GCM file encryption with Argon2id key derivation

