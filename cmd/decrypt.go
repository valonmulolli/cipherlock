package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
	"golang.org/x/term"
)

var (
	decryptOutput   string
	decryptKeyFile  string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [flags] <path>",
	Short: "Decrypt a file",
	Long: `Decrypt a file previously encrypted with cipherlock.

Supports both the current V2 format (Argon2id) and the legacy
V1 format (PBKDF2+SHA1) for backward compatibility.

If no output path is specified, the decrypted output strips the
.encrypted or .cipherlock extension, or appends .decrypted.

When <path> is "-", read encrypted data from stdin and write
plaintext to stdout.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]
		out := decryptOutput

		var password []byte
		var err error
		if decryptKeyFile != "" {
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

		if source == "-" {
			stat, _ := os.Stdout.Stat()
			bar := progressbar.NewOptions64(
				-1,
				progressbar.OptionSetDescription("decrypting"),
				progressbar.OptionSetWriter(os.Stderr),
				progressbar.OptionShowBytes(true),
				progressbar.OptionSetWidth(30),
				progressbar.OptionThrottle(100),
				progressbar.OptionOnCompletion(func() {
					fmt.Fprint(os.Stderr, "\n")
				}),
			)

			if stat != nil && (stat.Mode()&os.ModeCharDevice) != 0 {
				bar = nil
			}

			if out == "" {
				err = decryptFromReader(os.Stdout, os.Stdin, password)
				if bar != nil {
					bar.Finish()
				}
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
			if bar != nil {
				bar.Finish()
			}
			if err != nil {
				return err
			}
			return nil
		}

		info, err := os.Stat(source)
		if err != nil {
			return err
		}

		if out == "" {
			out = defaultDecryptPath(source)
		}

		if inPlace {
			tmp := source + ".tmp"
			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}

			srcFile, err := os.Open(source)
			if err != nil {
				return err
			}

			err = decryptFromReader(destFile, srcFile, password)
			srcFile.Close()
			destFile.Close()
			if err != nil {
				os.Remove(tmp)
				if isAuthError(err) {
					return errors.New("decryption failed: wrong password or corrupted data")
				}
				return err
			}

			if err := cipherlock.Shred(source); err != nil {
				os.Remove(tmp)
				return err
			}
			return os.Rename(tmp, source)
		}

		destFile, err := os.Create(out)
		if err != nil {
			return err
		}
		defer destFile.Close()

		srcFile, err := os.Open(source)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		bar := progressbar.NewOptions64(
			info.Size(),
			progressbar.OptionSetDescription("decrypting"),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprint(os.Stderr, "\n")
			}),
		)
		defer bar.Finish()

		srcReader := progressbar.NewReader(srcFile, bar)
		if info.Size() == 0 {
			err = decryptFromReader(destFile, srcFile, password)
		} else {
			err = decryptFromReader(destFile, &srcReader, password)
		}
		if err != nil {
			os.Remove(out)
			if isAuthError(err) {
				return errors.New("decryption failed: wrong password or corrupted data")
			}
			return err
		}

		return nil
	},
}

func decryptFromReader(w io.Writer, r io.Reader, password []byte) error {
	ok, reader, err := cipherlock.IsArmoredReader(r)
	if err != nil {
		return err
	}

	if ok {
		data, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		decoded, err := cipherlock.UnarmorBytes(data)
		if err != nil {
			return err
		}
		return cipherlock.Decrypt(w, bytes.NewReader(decoded), password)
	}

	return cipherlock.Decrypt(w, reader, password)
}

func isAuthError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "decryption failed")
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
}
