## cipherlock rotor

Re-encrypt a file with a new password

### Synopsis

Decrypt a file with the old password and re-encrypt it with a new one.

The plaintext is never written to disk -- it streams through memory.

By default the re-keyed file overwrites the original. Use --output to
write to a different path (the original is preserved).

```
cipherlock rotor [flags] <file>
```

### Options

```
      --checksum                  enable integrity checksum on re-encrypted output
      --compress                  compress data with zstd before re-encryption
      --force                     overwrite existing output file without prompting
  -h, --help                      help for rotor
      --key-file string           read current password from file instead of prompting
      --keychain                  read current password from system keychain
      --new-key-file string       read new password from file instead of prompting
      --new-password-env string   read new password from environment variable
      --new-password-fd string    read new password from file descriptor number (e.g. 0 for stdin pipe)
      --new-password-stdin        read new password from stdin
  -o, --output string             output file path
      --password-env string       read current password from environment variable
      --password-fd string        read current password from file descriptor number (e.g. 0 for stdin pipe)
      --password-stdin            read current password from stdin
      --save-keychain             save new password to system keychain
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

