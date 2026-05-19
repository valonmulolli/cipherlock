package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
	"golang.org/x/term"
)

var (
	rekeyOutput string
	newPwdFile  string
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey [flags] <file>",
	Short: "Re-encrypt a file with a new password",
	Long: `Decrypt a file with the old password and re-encrypt it with a new one.

The plaintext is held in memory only -- never written to disk.

When --in-place is set, the original file is securely shredded after
re-keying. Otherwise, the re-keyed file replaces the original (the
old encrypted file is lost). Use --output to write to a new path.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]

		fmt.Fprint(os.Stderr, "Enter current password: ")
		oldPwd, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}

		var newPwd []byte
		if newPwdFile != "" {
			newPwd, err = os.ReadFile(newPwdFile)
			if err != nil {
				return fmt.Errorf("reading new key file: %w", err)
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter new password: ")
			newPwd, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}

			fmt.Fprint(os.Stderr, "Confirm new password: ")
			confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}

			if string(newPwd) != string(confirm) {
				return errors.New("new passwords do not match")
			}
			showStrength(newPwd)
		}

		dest := rekeyOutput
		if dest == "" {
			dest = source
		}

		srcFile, err := os.Open(source)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		stopKDF := showKDF()

		if dest == source || inPlace {
			tmp := source + ".tmp"
			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}

			err = cipherlock.ReKey(destFile, srcFile, oldPwd, newPwd, nil)
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

		destFile, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer destFile.Close()

		err = cipherlock.ReKey(destFile, srcFile, oldPwd, newPwd, nil)
		stopKDF()
		return err
	},
}

func init() {
	rootCmd.AddCommand(rekeyCmd)
	rekeyCmd.Flags().StringVar(&newPwdFile, "new-key-file", "", "read new password from file instead of prompting")
	rekeyCmd.Flags().StringVarP(&rekeyOutput, "output", "o", "", "output file path")
}
