package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var infoCmd = &cobra.Command{
	Use:   "tumbler [flags] <file>",
	Short: "Display encrypted file metadata",
	Long: `Show metadata about an encrypted cipherlock file.

Without --password, displays basic information (format version, whether
the file is encrypted, and cleartext metadata if available).

With --password, also displays the stored filename, original size, and
modification time.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		ok, err := cipherlock.IsEncrypted(path)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("not a cipherlock file: %s", path)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "File: %s\n", path)

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		meta, err := cipherlock.ReadStreamMeta(f)
		if err != nil {
			if errors.Is(err, cipherlock.ErrEncryptedMeta) && infoPassword != "" {
				f.Seek(0, 0)
				meta, err = cipherlock.ReadStreamMetaWithPassword(f, []byte(infoPassword))
				if err != nil {
					return fmt.Errorf("reading metadata: %w", err)
				}
			} else if !errors.Is(err, cipherlock.ErrEncryptedMeta) {
				return fmt.Errorf("reading metadata: %w", err)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Metadata: encrypted (use --password to view)")
				return nil
			}
		}

		if meta == nil {
			fmt.Fprintln(cmd.OutOrStdout(), "Metadata: none")
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Name:     %s\n", meta.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "Size:     %d bytes\n", meta.Size)
		fmt.Fprintf(cmd.OutOrStdout(), "Modified: %s\n", meta.ModTime.Format("2006-01-02 15:04:05"))
		return nil
	},
}

var infoPassword string

func init() {
	rootCmd.AddCommand(infoCmd)
	infoCmd.Flags().StringVar(&infoPassword, "password", "", "password to decrypt encrypted metadata")
}
