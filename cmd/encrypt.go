package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
	"golang.org/x/term"
)

var (
	outputPath       string
	genPassword      bool
	armorMode        bool
	keyFilePath      string
	checksumFlag     bool
	recipientPwds    []string
	recipientPubkeys []string
	passwordEnv      string
	passwordFD       string
	passwordStdin    bool
	profileName      string
	outDir           string
	keychainFlag     bool
	saveKeychain     bool
	forceEncrypt     bool
	jobs             int
	argonTime        uint32
	argonMemory      uint32
	argonThreads     uint8
	compressFlag     bool
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

		if len(recipientPubkeys) > 0 && len(recipientPwds) == 0 && !keychainFlag && keyFilePath == "" && passwordEnv == "" && passwordFD == "" && !passwordStdin && !genPassword {
			passwords = nil
		} else if keychainFlag {
			if keyFilePath != "" {
				return fmt.Errorf("--keychain and --key-file are mutually exclusive")
			}
			if len(recipientPwds) > 0 {
				return fmt.Errorf("--keychain cannot be used with --recipient")
			}
			pwd, err := resolvePassword(passwordSource{KeychainOn: true, KeychainAc: getKeychainAccount(args[0])})
			if err != nil {
				return err
			}
			defer clear(pwd)
			passwords = [][]byte{pwd}
		} else if len(recipientPwds) > 0 {
			for _, r := range recipientPwds {
				passwords = append(passwords, []byte(r))
			}
			primary, err := resolvePassword(passwordSource{
				FD: passwordFD, Env: passwordEnv, KeyFile: keyFilePath,
				Stdin: passwordStdin, Label: "Enter your password: ",
			})
			if err != nil {
				return err
			}
			defer clear(primary)
			showStrength(primary)
			passwords = append([][]byte{primary}, passwords...)
		} else {
			primary, err := resolvePassword(passwordSource{
				FD: passwordFD, Env: passwordEnv, KeyFile: keyFilePath,
				Stdin: passwordStdin, GenPwd: genPassword, Label: "Enter password: ",
			})
			if err != nil {
				return err
			}
			defer clear(primary)
			showStrength(primary)
			passwords = [][]byte{primary}
		}

		var asymmetricRecipients []*cipherlock.X25519Recipient

		if len(recipientPubkeys) > 0 {
			for _, path := range recipientPubkeys {
				data, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("reading recipient public key %q: %w", path, err)
				}
				raw := strings.TrimSpace(string(data))
				pubKey, err := base64.StdEncoding.DecodeString(raw)
				if err != nil {
					return fmt.Errorf("decoding public key %q: %w", path, err)
				}
				rec, err := cipherlock.NewX25519Recipient(pubKey)
				if err != nil {
					return fmt.Errorf("invalid public key %q: %w", path, err)
				}
				asymmetricRecipients = append(asymmetricRecipients, rec)
			}
		}

		if armorMode && len(asymmetricRecipients) == 0 {
			for _, p := range passwords {
				if len(p) == 0 {
					return errors.New("password cannot be empty in armor mode")
				}
			}
		}

		config := &cipherlock.Config{
			SaltLen:     cipherlock.DefaultConfig.SaltLen,
			Time:        cipherlock.DefaultConfig.Time,
			Memory:      cipherlock.DefaultConfig.Memory,
			Threads:     cipherlock.DefaultConfig.Threads,
			KeyLen:      cipherlock.DefaultConfig.KeyLen,
			Checksum:    checksumFlag,
			Compression: compressFlag,
		}

		if profileName != "" {
			profile, err := lookupProfile(profileName)
			if err != nil {
				return err
			}
			config.ApplyProfile(profile)
		}

		if argonTime > 0 {
			config.Time = argonTime
		}
		if argonMemory > 0 {
			config.Memory = argonMemory
		}
		if argonThreads > 0 {
			config.Threads = argonThreads
		}

		if err := validateEncryptFlags(args, outputPath, outDir, inPlace); err != nil {
			return err
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
				dest := outputPath
				if inPlace {
					dest = src
				} else if outDir != "" {
					dest = filepath.Join(outDir, filepath.Base(src)+".encrypted")
				} else if dest == "" {
					dest = src + ".encrypted"
				}
				fmt.Fprintf(os.Stderr, "would encrypt %s -> %s\n", src, dest)
			}
			return nil
		}

		if len(args) == 1 && args[0] == "-" {
			return encryptStdin(passwords, asymmetricRecipients, config)
		}

		if len(args) == 1 {
			info, err := os.Stat(args[0])
			if err != nil {
				return err
			}
			if info.IsDir() {
				if len(asymmetricRecipients) > 0 {
					return errors.New("asymmetric encryption not supported for directories")
				}
				if len(passwords) > 1 {
					return errors.New("multi-recipient encryption not supported for directories")
				}
				dest := outputPath
				if dest == "" {
					dest = strings.TrimRight(args[0], "/\\") + ".cipherlock"
				}
				if !forceEncrypt {
					if _, err := os.Stat(dest); err == nil {
						return fmt.Errorf("output %q exists; use --force to overwrite", dest)
					}
				}
				return cipherlock.EncryptDir(args[0], dest, passwords[0], config)
			}
		}

		var destPaths []string
		if jobs > 0 {
			err := processFilesInParallel(args, func(src string, info os.FileInfo) (string, error) {
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
				if !forceEncrypt && !inPlace && dest != "-" {
					if _, err := os.Stat(dest); err == nil {
						return "", fmt.Errorf("output %q exists; use --force to overwrite", dest)
					}
				}
				return dest, nil
			}, batchEncryptFunc(passwords, asymmetricRecipients, config), jobs)
			if saveKeychain {
				savePasswordsToKeychain(args, passwords)
			}
			return err
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

			if !forceEncrypt && !inPlace && dest != "-" {
				if _, err := os.Stat(dest); err == nil {
					return fmt.Errorf("output %q exists; use --force to overwrite", dest)
				}
			}

			if err := encryptFile(src, dest, info, passwords, asymmetricRecipients, config); err != nil {
				return err
			}
			destPaths = append(destPaths, dest)
		}

		if saveKeychain {
			savePasswordsToKeychain(destPaths, passwords)
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
	if keep && !inPlace {
		return fmt.Errorf("--keep requires --in-place")
	}
	if backup && !inPlace {
		return fmt.Errorf("--backup requires --in-place")
	}
	if keep && backup {
		return fmt.Errorf("--keep and --backup are mutually exclusive")
	}
	return nil
}

func encryptStdin(passwords [][]byte, asymmetricRecipients []*cipherlock.X25519Recipient, config *cipherlock.Config) error {
	out := outputPath
	stopKDF := showKDF()

	if out == "" || out == "-" {
		err := encryptToWriter(os.Stdout, os.Stdin, passwords, asymmetricRecipients, config)
		stopKDF()
		return err
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	err = encryptToWriter(f, os.Stdin, passwords, asymmetricRecipients, config)
	stopKDF()
	return err
}

func encryptFile(srcPath, dstPath string, info os.FileInfo, passwords [][]byte, asymmetricRecipients []*cipherlock.X25519Recipient, config *cipherlock.Config) (err error) {
	defer func() { quietStatus("encrypted", err) }()
	if info == nil {
		var err error
		info, err = os.Stat(srcPath)
		if err != nil {
			return err
		}
	}

	cfg := *config
	cfg.FileMeta = &cipherlock.FileMeta{
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

		err := inPlaceWrite(srcPath, keep, func(tmp, _ string) error {
			destFile, err := os.Create(tmp)
			if err != nil {
				return err
			}
			defer destFile.Close()

			stopKDF := showKDF()
			err = encryptToWriter(destFile, srcReader, passwords, asymmetricRecipients, &cfg)
			stopKDF()
			return err
		})
		srcFile.Close()
		return err
	}

	defer srcFile.Close()

	srcReader := progressReader(srcFile, info.Size(), "encrypting")
	stopKDF := showKDF()

	if dstPath == "-" {
		err = encryptToWriter(os.Stdout, srcReader, passwords, asymmetricRecipients, &cfg)
		stopKDF()
		return err
	}

	destFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}

	err = encryptToWriter(destFile, srcReader, passwords, asymmetricRecipients, &cfg)
	stopKDF()
	if closeErr := destFile.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(dstPath) //nolint:errcheck
	}
	return err
}

func encryptToWriter(w io.Writer, r io.Reader, passwords [][]byte, asymmetricRecipients []*cipherlock.X25519Recipient, config *cipherlock.Config) error {
	if len(asymmetricRecipients) > 0 {
		encryptFn := func(dst io.Writer, src io.Reader, recs []*cipherlock.X25519Recipient, cfg *cipherlock.Config) error {
			return cipherlock.EncryptAsymmetric(dst, src, recs, cfg)
		}
		if !armorMode {
			return encryptFn(w, r, asymmetricRecipients, config)
		}
		aw := cipherlock.NewArmorWriter(w)
		defer aw.Close() //nolint:errcheck
		return encryptFn(aw, r, asymmetricRecipients, config)
	}

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
	encryptCmd.Flags().StringArrayVar(&recipientPubkeys, "recipient-pubkey", nil, "path to recipient's X25519 public key file (can be specified multiple times)")
	encryptCmd.Flags().StringVar(&profileName, "profile", "", "use a saved configuration profile")
	encryptCmd.Flags().StringVar(&outDir, "out-dir", "", "output directory for batch encryption")
	encryptCmd.Flags().BoolVar(&keychainFlag, "keychain", false, "read password from system keychain")
	encryptCmd.Flags().BoolVar(&saveKeychain, "save-keychain", false, "save password to system keychain after encryption")
	encryptCmd.Flags().BoolVar(&forceEncrypt, "force", false, "overwrite existing output files without prompting")
	encryptCmd.Flags().StringVar(&passwordEnv, "password-env", "", "read password from environment variable")
	encryptCmd.Flags().StringVar(&passwordFD, "password-fd", "", "read password from file descriptor number (e.g. 0 for stdin pipe)")
	encryptCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
	encryptCmd.Flags().IntVarP(&jobs, "jobs", "j", 0, "number of parallel jobs (default: sequential)")
	encryptCmd.Flags().Uint32Var(&argonTime, "time", 0, "Argon2id time parameter (overrides profile)")
	encryptCmd.Flags().Uint32Var(&argonMemory, "memory", 0, "Argon2id memory in KB (overrides profile)")
	encryptCmd.Flags().Uint8Var(&argonThreads, "threads", 0, "Argon2id parallelism (overrides profile)")
	encryptCmd.Flags().BoolVar(&compressFlag, "compress", false, "compress data with zstd before encryption")
	encryptCmd.RegisterFlagCompletionFunc("profile", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return profileNames(), cobra.ShellCompDirectiveDefault
	})
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	return err
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
			clear(p1)
			return nil, err
		}

		if string(p1) == string(p2) {
			clear(p2)
			return p1, nil
		}

		clear(p1)
		clear(p2)
		fmt.Fprintln(os.Stderr, "Passwords do not match. Try again.")
	}

	return nil, errors.New("too many failed attempts")
}
