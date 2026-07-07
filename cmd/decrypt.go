package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var (
	decryptOutput        string
	decryptKeyFile       string
	decryptOutDir        string
	checkOnly            bool
	forceOverwrite       bool
	decryptDirMode       bool
	identityFile         string
	decryptPasswordFD    string
	decryptPasswordEnv   string
	decryptPasswordStdin bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [flags] <path> [<path>...]",
	Short: "Decrypt a file",
	Long: `Decrypt one or more files previously encrypted with cipherlock.

Supports both the current V2 format (Argon2id) and the legacy
V1 format (PBKDF2+SHA1) for backward compatibility.

If no output path is specified, the decrypted output strips the
.encrypted or .cipherlock extension, or appends .decrypted.
Use --out-dir to write all outputs to a specific directory.

When <path> is "-", read encrypted data from stdin and write
plaintext to stdout.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("requires at least one path argument")
		}

		if decryptOutDir != "" && decryptOutput != "" {
			return fmt.Errorf("--output and --out-dir are mutually exclusive")
		}
		if inPlace && (decryptOutput != "" || decryptOutDir != "") {
			return fmt.Errorf("--in-place is mutually exclusive with --output and --out-dir")
		}
		if decryptOutput != "" && len(args) > 1 {
			return fmt.Errorf("--output cannot be used with multiple input files")
		}

		if recursive {
			var err error
			args, err = expandArgs(args)
			if err != nil {
				return err
			}
		}

		if dryRun {
			for _, src := range args {
				dest := decryptOutput
				if inPlace {
					dest = src
				} else if decryptOutDir != "" {
					dest = filepath.Join(decryptOutDir, filepath.Base(defaultDecryptPath(src)))
				} else if dest == "" {
					dest = defaultDecryptPath(src)
				}
				fmt.Fprintf(os.Stderr, "would decrypt %s -> %s\n", src, dest)
			}
			return nil
		}

		var identity *cipherlock.X25519Identity
		if identityFile != "" {
			data, err := os.ReadFile(identityFile)
			if err != nil {
				return fmt.Errorf("reading identity file: %w", err)
			}
			identity, err = cipherlock.DeserializeX25519Identity(data, nil)
			if errors.Is(err, cipherlock.ErrIdentityNeedsPassphrase) {
				passphrase, e := readIdentityPassphrase()
				if e != nil {
					return fmt.Errorf("parsing identity file: %w", e)
				}
				defer clear(passphrase)
				identity, err = cipherlock.DeserializeX25519Identity(data, passphrase)
			}
			if err != nil && identity == nil {
				identity, err = cipherlock.IdentityFromSSHPrivateKey(data)
			}
			if err != nil {
				return fmt.Errorf("parsing identity file: %w", err)
			}
		}

		if identity != nil {
			if keychainFlag {
				return fmt.Errorf("--keychain cannot be used with --identity")
			}
			if decryptKeyFile != "" {
				return fmt.Errorf("--key-file cannot be used with --identity")
			}
			if decryptDirMode {
				return fmt.Errorf("--dir cannot be used with --identity")
			}

			for _, src := range args {
				if src == "-" {
					err := decryptAsymmetricFromReader(os.Stdout, os.Stdin, identity)
					return err
				}

				info, err := os.Stat(src)
				if err != nil {
					return err
				}

				if checkOnly {
					srcFile, err := os.Open(src)
					if err != nil {
						return err
					}
					var reader io.Reader
					if info.Size() > 0 && info.Mode().IsRegular() {
						reader = progressReader(srcFile, info.Size(), "checking")
					} else {
						reader = srcFile
					}
					err = decryptAsymmetricFromReader(io.Discard, reader, identity)
					srcFile.Close()
					if err != nil {
						if isAuthError(err) {
							return errors.New("decryption failed: wrong identity or corrupted data")
						}
						return err
					}
					return nil
				}

				dest := decryptOutput
				if inPlace {
					dest = src
				} else if dest == "" {
					if decryptOutDir != "" {
						dest = filepath.Join(decryptOutDir, filepath.Base(defaultDecryptPath(src)))
					} else {
						dest = defaultDecryptPath(src)
					}
				}

				if !forceOverwrite && !inPlace && dest != "-" {
					if _, err := os.Stat(dest); err == nil {
						return fmt.Errorf("output %q exists; use --force to overwrite", dest)
					}
				}

				err = decryptAsymmetricFile(dest, src, info, identity)
				if err != nil {
					if isAuthError(err) {
						return errors.New("decryption failed: wrong identity or corrupted data")
					}
					return err
				}
			}
			return nil
		}

		var password []byte
		if keychainFlag {
			if decryptKeyFile != "" {
				return fmt.Errorf("--keychain and --key-file are mutually exclusive")
			}
			pwd, err := resolvePassword(passwordSource{KeychainOn: true, KeychainAc: getKeychainAccount(args[0])})
			if err != nil {
				return err
			}
			password = pwd
			defer clear(password)
		} else {
			pwd, err := resolvePassword(passwordSource{
				FD: decryptPasswordFD, Env: decryptPasswordEnv, KeyFile: decryptKeyFile,
				Stdin: decryptPasswordStdin, Label: "Enter password: ",
			})
			if err != nil {
				return err
			}
			password = pwd
			defer clear(password)
		}

		if len(args) == 1 && args[0] == "-" {
			if checkOnly {
				stopKDF := showKDF()
				err := decryptFromReader(io.Discard, os.Stdin, password)
				stopKDF()
				return err
			}
			return decryptStdin(password)
		}

		var destPaths []string
		if jobs > 0 {
			err := processFilesInParallel(args, func(src string, info os.FileInfo) (string, error) {
				if checkOnly || decryptDirMode {
					return "", nil
				}
				dest := decryptOutput
				if inPlace {
					dest = src
				} else if dest == "" {
					if decryptOutDir != "" {
						dest = filepath.Join(decryptOutDir, filepath.Base(defaultDecryptPath(src)))
					} else {
						dest = defaultDecryptPath(src)
					}
				}
				if !forceOverwrite && !inPlace && dest != "-" {
					if _, err := os.Stat(dest); err == nil {
						return "", fmt.Errorf("output %q exists; use --force to overwrite", dest)
					}
				}
				return dest, nil
			}, batchDecryptFunc(password, identity), jobs)
			if saveKeychain && err == nil {
				savePasswordsToKeychain(args, [][]byte{password})
			}
			return err
		}

		for _, src := range args {
			info, err := os.Stat(src)
			if err != nil {
				return err
			}

			if checkOnly {
				if err := checkDecrypt(src, info, password); err != nil {
					return err
				}
				continue
			}

			if decryptDirMode {
				return decryptDirSource(src, info, password)
			}

			dest := decryptOutput
			if inPlace {
				dest = src
			} else if dest == "" {
				if decryptOutDir != "" {
					dest = filepath.Join(decryptOutDir, filepath.Base(defaultDecryptPath(src)))
				} else {
					dest = defaultDecryptPath(src)
				}
			}

			if !forceOverwrite && !inPlace && dest != "-" {
				if _, err := os.Stat(dest); err == nil {
					return fmt.Errorf("output %q exists; use --force to overwrite", dest)
				}
			}

			if err := decryptFile(src, dest, info, password); err != nil {
				return err
			}
			destPaths = append(destPaths, dest)
		}

		if saveKeychain {
			savePasswordsToKeychain(destPaths, [][]byte{password})
		}

		return nil
	},
}

func checkDecrypt(srcPath string, info os.FileInfo, password []byte) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	var reader io.Reader
	if info.Size() > 0 && info.Mode().IsRegular() {
		reader = progressReader(srcFile, info.Size(), "checking")
	} else {
		reader = srcFile
	}

	stopKDF := showKDF()
	err = decryptFromReader(io.Discard, reader, password)
	stopKDF()
	return err
}

func decryptStdin(password []byte) error {
	out := decryptOutput
	stopKDF := showKDF()

	if out == "" || out == "-" {
		err := decryptFromReader(os.Stdout, os.Stdin, password)
		stopKDF()
		return err
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	err = decryptFromReader(f, os.Stdin, password)
	stopKDF()
	return err
}

func decryptDirSource(srcPath string, info os.FileInfo, password []byte) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", srcPath)
	}

	dest := decryptOutput
	if inPlace {
		dest = srcPath
	} else if dest == "" {
		if decryptOutDir != "" {
			dest = filepath.Join(decryptOutDir, filepath.Base(defaultDecryptPath(srcPath)))
		} else {
			dest = defaultDecryptPath(srcPath)
		}
	}

	if !forceOverwrite && !inPlace {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("output %q exists; use --force to overwrite", dest)
		}
	}

	if err := cipherlock.DecryptDir(srcPath, dest, password); err != nil {
		if isAuthError(err) {
			return errors.New("decryption failed: wrong password or corrupted data")
		}
		return err
	}

	if inPlace {
		_ = cipherlock.Shred(srcPath)
	}

	return nil
}

func decryptFile(srcPath, dstPath string, info os.FileInfo, password []byte) (err error) {
	defer func() { quietStatus("decrypted", err) }()
	if inPlace {
		return inPlaceWrite(srcPath, keep, func(tmp, bak string) error {
			srcFile, err := os.Open(bak)
			if err != nil {
				return err
			}
			defer srcFile.Close()

			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}
			defer destFile.Close()

			srcReader := progressReader(srcFile, info.Size(), "decrypting")
			stopKDF := showKDF()
			err = decryptFromReader(destFile, srcReader, password)
			stopKDF()
			if isAuthError(err) {
				return errors.New("decryption failed: wrong password or corrupted data")
			}
			return err
		})
	}

	if dstPath == "-" {
		srcFile, srcErr := os.Open(srcPath)
		if srcErr != nil {
			return srcErr
		}
		defer srcFile.Close()
		srcReader := progressReader(srcFile, info.Size(), "decrypting")
		stopKDF := showKDF()
		err = decryptFromReader(os.Stdout, srcReader, password)
		stopKDF()
		if isAuthError(err) {
			return errors.New("decryption failed: wrong password or corrupted data")
		}
		return err
	}

	destFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		destFile.Close()
		return err
	}
	defer srcFile.Close() //nolint:errcheck

	srcReader := progressReader(srcFile, info.Size(), "decrypting")
	stopKDF := showKDF()

	if info.Size() == 0 {
		err = decryptFromReader(destFile, srcFile, password)
	} else {
		err = decryptFromReader(destFile, srcReader, password)
	}
	stopKDF()
	closeErr := destFile.Close()
	if err != nil {
		os.Remove(dstPath) //nolint:errcheck
		if isAuthError(err) {
			return errors.New("decryption failed: wrong password or corrupted data")
		}
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	restoreMeta(srcPath, dstPath, password, decryptOutput != "")
	return nil
}

func decryptFromReader(w io.Writer, r io.Reader, password []byte) error {
	ok, reader, err := cipherlock.IsArmoredReader(r)
	if err != nil {
		return err
	}

	if ok {
		ur, err := cipherlock.NewUnarmorReader(reader)
		if err != nil {
			return err
		}
		return cipherlock.Decrypt(w, ur, password)
	}

	return cipherlock.Decrypt(w, reader, password)
}

func decryptAsymmetricFromReader(w io.Writer, r io.Reader, identity *cipherlock.X25519Identity) error {
	ok, reader, err := cipherlock.IsArmoredReader(r)
	if err != nil {
		return err
	}

	if ok {
		ur, err := cipherlock.NewUnarmorReader(reader)
		if err != nil {
			return err
		}
		return cipherlock.DecryptAsymmetric(w, ur, identity)
	}

	return cipherlock.DecryptAsymmetric(w, reader, identity)
}

func decryptAsymmetricFile(dstPath string, srcPath string, info os.FileInfo, identity *cipherlock.X25519Identity) (err error) {
	defer func() { quietStatus("decrypted", err) }()
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	var reader io.Reader
	if info.Size() > 0 && info.Mode().IsRegular() {
		reader = progressReader(srcFile, info.Size(), "decrypting")
	} else {
		reader = srcFile
	}

	if inPlace {
		srcFile.Close()
		return inPlaceWrite(srcPath, keep, func(tmp, bak string) error {
			bakFile, err := os.Open(bak)
			if err != nil {
				return err
			}
			defer bakFile.Close()

			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}
			defer destFile.Close()

			var bakReader io.Reader
			if info.Size() > 0 && info.Mode().IsRegular() {
				bakReader = progressReader(bakFile, info.Size(), "decrypting")
			} else {
				bakReader = bakFile
			}

			return decryptAsymmetricFromReader(destFile, bakReader, identity)
		})
	}

	if dstPath == "-" {
		return decryptAsymmetricFromReader(os.Stdout, reader, identity)
	}

	destFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	err = decryptAsymmetricFromReader(destFile, reader, identity)
	if err != nil {
		os.Remove(dstPath) //nolint:errcheck
	}
	return err
}

func restoreMeta(encPath, decPath string, password []byte, userSetOutput bool) {
	encFile, err := os.Open(encPath)
	if err != nil {
		return
	}
	defer encFile.Close() //nolint:errcheck

	meta, err := cipherlock.ReadStreamMeta(encFile)
	if err != nil {
		if errors.Is(err, cipherlock.ErrEncryptedMeta) && len(password) > 0 {
			if _, err := encFile.Seek(0, 0); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to seek encrypted file for metadata: %v\n", err)
				return
			}
			meta, err = cipherlock.ReadStreamMetaWithPassword(encFile, password)
			if err != nil {
				return
			}
		} else {
			return
		}
	}
	if meta == nil {
		return
	}

	if !userSetOutput && meta.Name != "" {
		dir := filepath.Dir(decPath)
		restoredName := filepath.Join(dir, meta.Name)
		if restoredName != decPath {
			if err := os.Rename(decPath, restoredName); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to restore original filename: %v\n", err)
				return
			}
			decPath = restoredName
		}
	}

	if err := os.Chtimes(decPath, meta.ModTime, meta.ModTime); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to restore modification time: %v\n", err)
	}
}

func isAuthError(err error) bool {
	return errors.Is(err, cipherlock.ErrAuthFailed)
}

func defaultDecryptPath(source string) string {
	if strings.HasSuffix(source, ".encrypted") {
		return strings.TrimSuffix(source, ".encrypted")
	}
	if strings.HasSuffix(source, ".cipherlock") {
		return strings.TrimSuffix(source, ".cipherlock")
	}
	return source + ".decrypted"
}

func readIdentityPassphrase() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Identity passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase required for encrypted identity")
	}
	return passphrase, nil
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "output file path")
	decryptCmd.Flags().StringVar(&decryptKeyFile, "key-file", "", "read password from file instead of prompting")
	decryptCmd.Flags().StringVar(&decryptOutDir, "out-dir", "", "output directory for batch decryption")
	decryptCmd.Flags().BoolVar(&keychainFlag, "keychain", false, "read password from system keychain")
	decryptCmd.Flags().BoolVar(&saveKeychain, "save-keychain", false, "save password to system keychain after decryption")
	decryptCmd.Flags().BoolVar(&checkOnly, "check", false, "verify password and format without writing output")
	decryptCmd.Flags().BoolVar(&forceOverwrite, "force", false, "overwrite existing output files without prompting")
	decryptCmd.Flags().BoolVar(&decryptDirMode, "dir", false, "decrypt directory archive and extract")
	decryptCmd.Flags().StringVar(&identityFile, "identity", "", "path to X25519 identity (private key) file for asymmetric decryption")
	decryptCmd.Flags().StringVar(&decryptPasswordEnv, "password-env", "", "read password from environment variable")
	decryptCmd.Flags().StringVar(&decryptPasswordFD, "password-fd", "", "read password from file descriptor number (e.g. 0 for stdin pipe)")
	decryptCmd.Flags().BoolVar(&decryptPasswordStdin, "password-stdin", false, "read password from stdin")
	decryptCmd.Flags().IntVarP(&jobs, "jobs", "j", 0, "number of parallel workers (default: sequential)")
}
