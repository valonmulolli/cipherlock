## cipherlock gate decrypt

Decrypt a time-gated file

### Synopsis

Decrypt a file that was encrypted with an expiration time.

If the current time is past the expiration time embedded in the file,
the decryption will fail.

```
cipherlock gate decrypt [flags] <path>
```

### Options

```
      --force                 overwrite existing output file without prompting
  -h, --help                  help for decrypt
      --in-place              overwrite source on success
      --output string         output file path
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
      --include string   only process files matching this glob pattern
      --keep             keep the original file (opposite of --in-place)
      --quiet            suppress progress output
      --recursive        process directories recursively
```

### SEE ALSO

* [cipherlock gate](cipherlock_gate.md)	 - Time-gated file encryption

