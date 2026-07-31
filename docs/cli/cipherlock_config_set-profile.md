## cipherlock config set-profile

Create or update a configuration profile

```
cipherlock config set-profile <name> [flags]
```

### Options

```
      --checksum        enable checksum verification (default true)
  -h, --help            help for set-profile
      --memory uint32   Argon2id memory parameter in KB (default 65536)
      --threads uint8   Argon2id parallelism (default 4)
      --time uint32     Argon2id time parameter (default 3)
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

* [cipherlock config](cipherlock_config.md)	 - Manage configuration profiles

