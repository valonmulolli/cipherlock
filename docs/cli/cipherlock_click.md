## cipherlock click

Verify password and file integrity

### Synopsis

Quickly verify that a password is correct for an encrypted file.

The command decrypts the file header to check if the password is valid
without writing any output. Returns exit code 0 if the password is correct
and the file is intact, or a non-zero exit code otherwise.

This is the same as 'decrypt --check'.

```
cipherlock click [flags] <file>
```

### Options

```
  -h, --help                  help for click
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

