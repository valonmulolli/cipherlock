package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
	"golang.org/x/term"
)

var (
	outputPath  string
	genPassword bool
	armorMode   bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [flags] <path>",
	Short: "Encrypt a file or directory",
	Long: `Encrypt a file or entire directory.

If <path> is a regular file, it is encrypted with AES-256-GCM.
If <path> is a directory, it is archived (tar+gzip) before encryption.

If no output path is specified, the encrypted output is written to
<path>.encrypted for files or <path>.cipherlock for directories.
Use --in-place to overwrite the source after successful encryption.
Use --gen-password to generate a cryptographically random password.

When <path> is "-", read from stdin and write encrypted data to stdout.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]
		var password []byte
		var err error

		if genPassword {
			pwd, err := generatePassword(32)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "password:", string(pwd))
			password = pwd
		} else {
			password, err = promptPassword("Enter password: ", true)
			if err != nil {
				return err
			}
		}

		if armorMode && len(password) == 0 {
			return errors.New("password cannot be empty in armor mode")
		}

		config := cipherlock.DefaultConfig

		out := outputPath
		destIsSet := out != ""

		if source == "-" {
			if !destIsSet {
				out = ""
			}
			stat, _ := os.Stdout.Stat()
			bar := progressbar.NewOptions64(
				-1,
				progressbar.OptionSetDescription("encrypting"),
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
				err = encryptToWriter(os.Stdout, os.Stdin, password, config)
				if bar != nil {
					bar.Finish()
				}
				return err
			}

			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()

			err = encryptToWriter(f, os.Stdin, password, config)
			if bar != nil {
				bar.Finish()
			}
			return err
		}

		info, err := os.Stat(source)
		if err != nil {
			return err
		}

		if info.IsDir() {
			if !destIsSet {
				out = source + ".cipherlock"
			}
			return cipherlock.EncryptDir(source, out, password, config)
		}

		if !destIsSet {
			out = source + ".encrypted"
		}

		srcFile, err := os.Open(source)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		if inPlace {
			tmp := source + ".tmp"
			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}

			bar := progressbar.NewOptions64(
				info.Size(),
				progressbar.OptionSetDescription("encrypting"),
				progressbar.OptionSetWriter(os.Stderr),
				progressbar.OptionShowBytes(true),
				progressbar.OptionSetWidth(30),
				progressbar.OptionThrottle(100),
				progressbar.OptionOnCompletion(func() {
					fmt.Fprint(os.Stderr, "\n")
				}),
			)
			destWriter := ioWriteCloser{Writer: bar, Closer: destFile}
			if info.Size() == 0 {
				destWriter = ioWriteCloser{Writer: destFile, Closer: destFile}
			}

			err = encryptToWriter(destWriter, srcFile, password, config)
			destFile.Close()
			if err != nil {
				os.Remove(tmp)
				return err
			}
			bar.Finish()

			return os.Rename(tmp, source)
		}

		destFile, err := os.Create(out)
		if err != nil {
			return err
		}
		defer destFile.Close()

		bar := progressbar.NewOptions64(
			info.Size(),
			progressbar.OptionSetDescription("encrypting"),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprint(os.Stderr, "\n")
			}),
		)
		defer bar.Finish()

		destWriter := ioWriteCloser{Writer: bar, Closer: destFile}
		if info.Size() == 0 {
			destWriter = ioWriteCloser{Writer: destFile, Closer: destFile}
		}

		return encryptToWriter(destWriter, srcFile, password, config)
	},
}

func encryptToWriter(w io.Writer, r io.Reader, password []byte, config *cipherlock.Config) error {
	if !armorMode {
		return cipherlock.Encrypt(w, r, password, config)
	}
	var buf bytes.Buffer
	if err := cipherlock.Encrypt(&buf, r, password, config); err != nil {
		return err
	}
	return cipherlock.Armor(w, buf.Bytes())
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path")
	encryptCmd.Flags().BoolVar(&genPassword, "gen-password", false, "generate a random password and print it to stderr")
	encryptCmd.Flags().BoolVar(&armorMode, "armor", false, "encode output in base64 ASCII-armor format")
}

type ioWriteCloser struct {
	io.Writer
	io.Closer
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
