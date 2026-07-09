package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

		isArmored, armoredReader, aErr := cipherlock.IsArmoredReader(f)
		var r io.Reader = f
		switch {
		case aErr != nil:
			r = f
		case isArmored:
			ur, uErr := cipherlock.NewUnarmorReader(armoredReader)
			if uErr == nil {
				r = ur
			}
		default:
			r = armoredReader
		}

		meta, err := cipherlock.ReadStreamMeta(r)
		if err != nil {
			if errors.Is(err, cipherlock.ErrEncryptedMeta) && infoPassword != "" {
				meta, err = func() (*cipherlock.FileMeta, error) {
					f2, e := os.Open(path)
					if e != nil {
						return nil, e
					}
					defer f2.Close()
					var r2 io.Reader
					ok2, ar2, pe := cipherlock.IsArmoredReader(f2)
					switch {
					case pe != nil:
						r2 = f2
					case ok2:
						ur2, ue := cipherlock.NewUnarmorReader(ar2)
						if ue != nil {
							return nil, ue
						}
						r2 = ur2
					default:
						r2 = ar2
					}
					data, e := io.ReadAll(r2)
					if e != nil {
						return nil, e
					}
					return cipherlock.ReadStreamMetaWithPassword(bytes.NewReader(data), []byte(infoPassword))
				}()
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
