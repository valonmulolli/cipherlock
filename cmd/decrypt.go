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
	decryptOutput  string
	decryptKeyFile string
	decryptOutDir  string
	checkOnly      bool
	forceOverwrite bool
	decryptDirMode bool
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

		var password []byte
		var err error
		if keychainFlag {
			if decryptKeyFile != "" {
				return fmt.Errorf("--keychain and --key-file are mutually exclusive")
			}
			pwdStr, err := keychainGet(getKeychainAccount(args[0]))
			if err != nil {
				return fmt.Errorf("keychain lookup failed: %w", err)
			}
			password = []byte(pwdStr)
		} else if decryptKeyFile != "" {
			password, err = os.ReadFile(decryptKeyFile)
			if err != nil {
				return fmt.Errorf("reading key file: %w", err)
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter password: ")
			password, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
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

			if !forceOverwrite && !inPlace {
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

	if out == "" {
		err := decryptFromReader(os.Stdout, os.Stdin, password)
		stopKDF()
		if err != nil {
			return err
		}
		return nil
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	err = decryptFromReader(f, os.Stdin, password)
	stopKDF()
	if err != nil {
		return err
	}
	return nil
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

func decryptFile(srcPath, dstPath string, info os.FileInfo, password []byte) error {
	if inPlace {
		tmp := srcPath + ".tmp"
		destFile, err := os.Create(tmp)
		if err != nil {
			return err
		}

		srcFile, err := os.Open(srcPath)
		if err != nil {
			destFile.Close()
			return err
		}

		srcReader := progressReader(srcFile, info.Size(), "decrypting")
		stopKDF := showKDF()

		err = decryptFromReader(destFile, srcReader, password)
		srcFile.Close()  //nolint:errcheck
		destFile.Close() //nolint:errcheck
		stopKDF()
		if err != nil {
			os.Remove(tmp) //nolint:errcheck
			if isAuthError(err) {
				return errors.New("decryption failed: wrong password or corrupted data")
			}
			return err
		}

		if err := cipherlock.Shred(srcPath); err != nil {
			os.Remove(tmp) //nolint:errcheck
			return err
		}
		return os.Rename(tmp, srcPath)
	}

	destFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer destFile.Close() //nolint:errcheck

	srcFile, err := os.Open(srcPath)
	if err != nil {
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
	if err != nil {
		os.Remove(dstPath) //nolint:errcheck
		if isAuthError(err) {
			return errors.New("decryption failed: wrong password or corrupted data")
		}
		return err
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

func restoreMeta(encPath, decPath string, password []byte, userSetOutput bool) {
	encFile, err := os.Open(encPath)
	if err != nil {
		return
	}
	defer encFile.Close() //nolint:errcheck

	meta, err := cipherlock.ReadStreamMeta(encFile)
	if err != nil {
		if errors.Is(err, cipherlock.ErrEncryptedMeta) && len(password) > 0 {
			encFile.Seek(0, 0) //nolint:errcheck
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
			_ = os.Rename(decPath, restoredName)
			decPath = restoredName
		}
	}

	_ = os.Chtimes(decPath, meta.ModTime, meta.ModTime)
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
}
