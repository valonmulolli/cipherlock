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
	outputPath     string
	genPassword    bool
	armorMode      bool
	keyFilePath    string
	checksumFlag   bool
	recipientPwds  []string
	profileName    string
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

		if armorMode && len(recipientPwds) == 0 && len(passwords[0]) == 0 {
			return errors.New("password cannot be empty in armor mode")
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

		if source != "-" {
			if st, stErr := os.Stat(source); stErr == nil && !st.IsDir() {
				config.FileMeta = &cipherlock.FileMeta{
					Name:    st.Name(),
					Size:    st.Size(),
					ModTime: st.ModTime(),
				}
			}
		}

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

			stopKDF := showKDF()

			if out == "" {
				err = encryptToWriter(os.Stdout, os.Stdin, passwords, config)
				stopKDF()
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

			err = encryptToWriter(f, os.Stdin, passwords, config)
			stopKDF()
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
			if len(passwords) > 1 {
				return errors.New("multi-recipient encryption not supported for directories")
			}
			if !destIsSet {
				out = source + ".cipherlock"
			}
			return cipherlock.EncryptDir(source, out, passwords[0], config)
		}

		if !destIsSet {
			out = source + ".encrypted"
		}

		srcFile, err := os.Open(source)
		if err != nil {
			return err
		}

		srcReader := progressReader(srcFile, info.Size(), "encrypting")
		stopKDF := showKDF()

		if inPlace {
			tmp := source + ".tmp"
			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}

			err = encryptToWriter(destFile, srcReader, passwords, config)
			srcFile.Close()
			destFile.Close()
			stopKDF()
			if err != nil {
				os.Remove(tmp)
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

		err = encryptToWriter(destFile, srcReader, passwords, config)
		stopKDF()
		return err
	},
}

func encryptToWriter(w io.Writer, r io.Reader, passwords [][]byte, config *cipherlock.Config) error {
	var encryptFn func(io.Writer, io.Reader, [][]byte, *cipherlock.Config) error
	if len(passwords) > 1 {
		encryptFn = func(dst io.Writer, src io.Reader, pwds [][]byte, cfg *cipherlock.Config) error {
			return cipherlock.EncryptMulti(dst, src, pwds, cfg)
		}
	} else {
		encryptFn = func(dst io.Writer, src io.Reader, pwds [][]byte, cfg *cipherlock.Config) error {
			return cipherlock.EncryptStream(dst, src, pwds[0], cfg)
		}
	}
	if !armorMode {
		return encryptFn(w, r, passwords, config)
	}
	var buf bytes.Buffer
	if err := encryptFn(&buf, r, passwords, config); err != nil {
		return err
	}
	return cipherlock.Armor(w, buf.Bytes())
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
