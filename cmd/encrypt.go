package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
	"golang.org/x/term"
)

var (
	outputPath    string
	genPassword   bool
	armorMode     bool
	keyFilePath   string
	checksumFlag  bool
	recipientPwds []string
	profileName   string
	outDir        string
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [flags] <path> [<path>...]",
	Short: "Encrypt a file or directory",
	Long: `Encrypt one or more files, or a single directory.

If <path> is a regular file, it is encrypted with AES-256-GCM.
If <path> is a directory, it is archived (tar+gzip) before encryption.
If multiple paths are given, they are all encrypted with the same password.

If no output path is specified, the encrypted output is written to
<path>.encrypted for files or <path>.cipherlock for directories.
Use --out-dir to write all outputs to a specific directory.
Use --in-place to overwrite the source after successful encryption.
Use --gen-password to generate a cryptographically random password.

When <path> is "-", read from stdin and write encrypted data to stdout.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("requires at least one path argument")
		}

		var passwords [][]byte
		var err error

		if len(recipientPwds) > 0 {
			for _, r := range recipientPwds {
				passwords = append(passwords, []byte(r))
			}
			if keyFilePath != "" {
				var pwd []byte
				pwd, err = os.ReadFile(keyFilePath)
				if err != nil {
					return fmt.Errorf("reading key file: %w", err)
				}
				passwords = append([][]byte{pwd}, passwords...)
			} else {
				var pwd []byte
				pwd, err = promptPassword("Enter your password: ", true)
				if err != nil {
					return err
				}
				showStrength(pwd)
				passwords = append([][]byte{pwd}, passwords...)
			}
		} else if keyFilePath != "" {
			var pwd []byte
			pwd, err = os.ReadFile(keyFilePath)
			if err != nil {
				return fmt.Errorf("reading key file: %w", err)
			}
			passwords = [][]byte{pwd}
		} else if genPassword {
			var pwd []byte
			pwd, err = generatePassword(32)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "password:", string(pwd))
			passwords = [][]byte{pwd}
		} else {
			var pwd []byte
			pwd, err = promptPassword("Enter password: ", true)
			if err != nil {
				return err
			}
			showStrength(pwd)
			passwords = [][]byte{pwd}
		}

		if armorMode {
			for _, p := range passwords {
				if len(p) == 0 {
					return errors.New("password cannot be empty in armor mode")
				}
			}
		}

		config := &cipherlock.Config{
			SaltLen:  cipherlock.DefaultConfig.SaltLen,
			Time:     cipherlock.DefaultConfig.Time,
			Memory:   cipherlock.DefaultConfig.Memory,
			Threads:  cipherlock.DefaultConfig.Threads,
			KeyLen:   cipherlock.DefaultConfig.KeyLen,
			Checksum: checksumFlag,
		}

		if profileName != "" {
			profile, err := lookupProfile(profileName)
			if err != nil {
				return err
			}
			config.ApplyProfile(profile)
		}

		if err := validateEncryptFlags(args, outputPath, outDir, inPlace); err != nil {
			return err
		}

		if len(args) == 1 && args[0] == "-" {
			return encryptStdin(passwords, config)
		}

		if len(args) == 1 {
			info, err := os.Stat(args[0])
			if err != nil {
				return err
			}
			if info.IsDir() {
				if len(passwords) > 1 {
					return errors.New("multi-recipient encryption not supported for directories")
				}
				dest := outputPath
				if dest == "" {
					dest = args[0] + ".cipherlock"
				}
				return cipherlock.EncryptDir(args[0], dest, passwords[0], config)
			}
		}

		for _, src := range args {
			info, err := os.Stat(src)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("cannot mix files and directories: %s", src)
			}

			dest := outputPath
			if inPlace {
				dest = src
			} else if dest == "" {
				if outDir != "" {
					dest = filepath.Join(outDir, filepath.Base(src)+".encrypted")
				} else {
					dest = src + ".encrypted"
				}
			}

			if err := encryptFile(src, dest, info, passwords, config); err != nil {
				return err
			}
		}

		return nil
	},
}

func validateEncryptFlags(args []string, output, outDir string, inPlace bool) error {
	if outDir != "" && output != "" {
		return fmt.Errorf("--output and --out-dir are mutually exclusive")
	}
	if inPlace && (output != "" || outDir != "") {
		return fmt.Errorf("--in-place is mutually exclusive with --output and --out-dir")
	}
	if output != "" && len(args) > 1 {
		return fmt.Errorf("--output cannot be used with multiple input files")
	}
	return nil
}

func encryptStdin(passwords [][]byte, config *cipherlock.Config) error {
	out := outputPath
	stopKDF := showKDF()

	if out == "" {
		err := encryptToWriter(os.Stdout, os.Stdin, passwords, config)
		stopKDF()
		return err
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	err = encryptToWriter(f, os.Stdin, passwords, config)
	stopKDF()
	return err
}

func encryptFile(srcPath, dstPath string, info os.FileInfo, passwords [][]byte, config *cipherlock.Config) error {
	if info == nil {
		var err error
		info, err = os.Stat(srcPath)
		if err != nil {
			return err
		}
	}

	config.FileMeta = &cipherlock.FileMeta{
		Name:    info.Name(),
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}

	if inPlace {
		srcReader := progressReader(srcFile, info.Size(), "encrypting")
		stopKDF := showKDF()

		tmp := srcPath + ".tmp"
		destFile, err := os.Create(tmp)
		if err != nil {
			srcFile.Close()
			return err
		}

		err = encryptToWriter(destFile, srcReader, passwords, config)
		destFile.Close()
		stopKDF()
		if err != nil {
			srcFile.Close()
			os.Remove(tmp)
			return err
		}

		srcFile.Close()
		if err := cipherlock.Shred(srcPath); err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, srcPath)
	}

	defer srcFile.Close()

	srcReader := progressReader(srcFile, info.Size(), "encrypting")
	stopKDF := showKDF()

	destFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	err = encryptToWriter(destFile, srcReader, passwords, config)
	stopKDF()
	return err
}

func encryptToWriter(w io.Writer, r io.Reader, passwords [][]byte, config *cipherlock.Config) error {
	var encryptFn func(io.Writer, io.Reader, [][]byte, *cipherlock.Config) error
	if len(passwords) > 1 {
		encryptFn = func(dst io.Writer, src io.Reader, pwds [][]byte, cfg *cipherlock.Config) error {
			return cipherlock.EncryptStreamMulti(dst, src, pwds, cfg)
		}
	} else {
		encryptFn = func(dst io.Writer, src io.Reader, pwds [][]byte, cfg *cipherlock.Config) error {
			if cfg != nil && cfg.FileMeta != nil {
				return cipherlock.EncryptStreamV2(dst, src, pwds[0], cfg)
			}
			return cipherlock.EncryptStream(dst, src, pwds[0], cfg)
		}
	}
	if !armorMode {
		return encryptFn(w, r, passwords, config)
	}
	aw := cipherlock.NewArmorWriter(w)
	defer aw.Close() //nolint:errcheck
	return encryptFn(aw, r, passwords, config)
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path")
	encryptCmd.Flags().BoolVar(&genPassword, "gen-password", false, "generate a random password and print it to stderr")
	encryptCmd.Flags().BoolVar(&armorMode, "armor", false, "encode output in base64 ASCII-armor format")
	encryptCmd.Flags().StringVar(&keyFilePath, "key-file", "", "read password from file instead of prompting")
	encryptCmd.Flags().BoolVar(&checksumFlag, "checksum", false, "embed SHA-256 checksum of plaintext and verify on decrypt")
	encryptCmd.Flags().StringArrayVar(&recipientPwds, "recipient", nil, "additional recipient password (can be specified multiple times)")
	encryptCmd.Flags().StringVar(&profileName, "profile", "", "use a saved configuration profile")
	encryptCmd.Flags().StringVar(&outDir, "out-dir", "", "output directory for batch encryption")
}

func generatePassword(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b)
	return dst, nil
}

func promptPassword(prompt string, confirm bool) ([]byte, error) {
	for attempts := 0; attempts < 3; attempts++ {
		fmt.Fprint(os.Stderr, prompt)
		p1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}

		if !confirm {
			return p1, nil
		}

		fmt.Fprint(os.Stderr, "Confirm password: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}

		if string(p1) == string(p2) {
			return p1, nil
		}

		fmt.Fprintln(os.Stderr, "Passwords do not match. Try again.")
	}

	return nil, errors.New("too many failed attempts")
}
