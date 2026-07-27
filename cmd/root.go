package cmd

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var defaultHelpFunc func(*cobra.Command, []string)

var (
	inPlace   bool
	quietFlag bool
	quiet     atomic.Bool
	keep      bool
	backup    bool
	dryRun    bool
	recursive bool
	include   string
	exclude   string
	color1    string // errors (#e3342f)
	color2    string // text/labels (#22808c)
	color3    string // spinner chars (#ffffff)
	color4    string // filled bar / gradient A (#32b8c6)
	color5    string // empty bar (#d6d5d4)
	color6    string // gradient B (#0f3639)
)

// Version is set at build time via -ldflags.
// Example: go build -ldflags "-X github.com/valonmulolli/cipherlock/cmd.Version=v1.2.0" .
// Falls back to the module version reported by debug.ReadBuildInfo()
// when installed with 'go install example/cipherlock@v1.2.0'.
var Version = "dev"

func init() {
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
	}
}

type helpStyles struct {
	banner  lipgloss.Style
	section lipgloss.Style
	cmd     lipgloss.Style
	desc    lipgloss.Style
	dim     lipgloss.Style
}

func newHelpStyles() helpStyles {
	var teal, white, gray lipgloss.Color

	if lipgloss.HasDarkBackground() {
		teal = lipgloss.Color("#22808c")
		white = lipgloss.Color("#ffffff")
		gray = lipgloss.Color("#d6d5d4")
	} else {
		teal = lipgloss.Color("#0a5c66")
		white = lipgloss.Color("#1a1a1a")
		gray = lipgloss.Color("#555555")
	}

	return helpStyles{
		banner: lipgloss.NewStyle().
			Bold(true).
			Foreground(teal).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(teal).
			Padding(0, 2).
			Width(60).
			Align(lipgloss.Center),
		section: lipgloss.NewStyle().
			Bold(true).
			Foreground(teal),
		cmd: lipgloss.NewStyle().
			Foreground(white).
			Width(22),
		desc: lipgloss.NewStyle().
			Foreground(gray),
		dim: lipgloss.NewStyle().
			Foreground(gray),
	}
}

var rootCmd = &cobra.Command{
	Use:   "cipherlock",
	Short: "AES-256-GCM file encryption with Argon2id key derivation",
	Long: `cipherlock encrypts and decrypts files using AES-256-GCM authenticated
encryption with Argon2id memory-hard key derivation.

It supports single files, entire directories, and stdin/stdout pipe mode.`,
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var animateCharset = "0123456789abcdefABCDEF~!@#$%^&*()+=_"

func lerpRGB(a, b rgb, t float64) rgb {
	return rgb{
		uint8(float64(a.r)*(1-t) + float64(b.r)*t),
		uint8(float64(a.g)*(1-t) + float64(b.g)*t),
		uint8(float64(a.b)*(1-t) + float64(b.b)*t),
	}
}

func animateBanner(w *os.File, s helpStyles) {
	finalRunes := []rune("cipherlock  ·  AES-256-GCM  ·  Argon2id  ·  X25519")
	charCount := len(finalRunes)

	if !term.IsTerminal(int(w.Fd())) || disabledColor() {
		fmt.Fprintln(w, s.banner.Render(string(finalRunes)))
		fmt.Fprintln(w)
		return
	}

	white := ansiFg(rgb{0xff, 0xff, 0xff})
	reset := ansiReset()

	col2 := rgb{0x22, 0x80, 0x8c}
	col4 := rgb{0x32, 0xb8, 0xc6}
	col6 := rgb{0x0f, 0x36, 0x39}

	inner := 58
	pad := 4
	cd1 := "\033[1B"
	cu2 := "\033[2A"
	cd2 := "\033[2B"

	drawBar := func(n int) string { return strings.Repeat("─", n) }
	drawGap := func(n int) string { return strings.Repeat(" ", n) }

	half := inner / 2
	for i := 0; i <= half; i++ {
		bar := drawBar(i)
		gap := drawGap(inner - 2*i)
		fmt.Fprint(w, "\r"+ansiFg(col2)+"╭"+bar+gap+bar+"╮"+reset)
		time.Sleep(6 * time.Millisecond)
	}
	fmt.Fprintln(w)

	var allScrambled strings.Builder
	for j := 0; j < charCount; j++ {
		t := float64(j) / float64(charCount)
		allScrambled.WriteString(ansiFg(lerpRGB(col4, col6, t)))
		allScrambled.WriteByte(animateCharset[rand.Intn(len(animateCharset))])
	}
	allScrambled.WriteString(reset)

	contentLine := ansiFg(col2) + "│" + drawGap(pad) + reset +
		allScrambled.String() + ansiFg(col2) + drawGap(pad) + "│" + reset
	fmt.Fprintln(w, contentLine)
	fmt.Fprint(w, ansiFg(col2)+"╰"+drawGap(inner)+"╯"+reset)
	fmt.Fprint(w, cu2)

	bottomOffset := charCount - half
	for i := 0; i <= charCount; i++ {
		progress := float64(i) / float64(charCount)

		var reveal strings.Builder
		reveal.WriteString(white)
		reveal.WriteString(string(finalRunes[:i]))
		reveal.WriteString(reset)

		remaining := charCount - i
		if remaining > 0 {
			for j := 0; j < remaining; j++ {
				t := float64(j) / float64(remaining)
				reveal.WriteString(ansiFg(lerpRGB(col4, col6, t)))
				reveal.WriteByte(animateCharset[rand.Intn(len(animateCharset))])
			}
			reveal.WriteString(reset)
		}

		borderColor := lerpRGB(col2, col4, progress*2)
		if progress >= 0.5 {
			borderColor = lerpRGB(col4, col2, (progress-0.5)*2)
		}

		fmt.Fprint(w, cd1)
		fmt.Fprint(w, "\r"+ansiFg(borderColor)+"│"+drawGap(pad)+reset+
			reveal.String()+ansiFg(borderColor)+drawGap(pad)+"│"+reset)
		fmt.Fprint(w, cd1)
		borderI := i - bottomOffset
		if borderI < 0 {
			borderI = 0
		}
		if borderI > half {
			borderI = half
		}
		bar := drawBar(borderI)
		gap := drawGap(inner - 2*borderI)
		fmt.Fprint(w, "\r"+ansiFg(borderColor)+"╰"+bar+gap+bar+"╯"+reset)
		fmt.Fprint(w, cu2)

		if i < charCount {
			time.Sleep(time.Duration(10+progress*30) * time.Millisecond)
		}
	}

	fmt.Fprint(w, cd2)

	time.Sleep(80 * time.Millisecond)
	fmt.Fprint(w, "\r"+white+"╰"+drawBar(inner)+"╯"+reset)
	time.Sleep(80 * time.Millisecond)
	fmt.Fprint(w, "\r"+ansiFg(col2)+"╰"+drawBar(inner)+"╯"+reset)
	time.Sleep(40 * time.Millisecond)

	fmt.Fprintln(w)
	fmt.Fprintln(w)
}

func init() {
	defaultHelpFunc = rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		w := cmd.OutOrStdout()
		s := newHelpStyles()

		var termFile *os.File
		if f, ok := w.(*os.File); ok {
			termFile = f
		}
		isAnim := termFile != nil && term.IsTerminal(int(termFile.Fd())) && !disabledColor()

		col4 := rgb{0x32, 0xb8, 0xc6}
		col6 := rgb{0x0f, 0x36, 0x39}
		wht := ansiFg(rgb{0xff, 0xff, 0xff})
		rst := ansiReset()

		padName := func(n string) string {
			r := []rune(n)
			if len(r) >= 22 {
				return string(r[:22])
			}
			return n + strings.Repeat(" ", 22-len(r))
		}

		scrambleLine := func(plain, styled string, speed time.Duration) {
			if !isAnim {
				fmt.Fprintf(w, "  %s\n", styled)
				return
			}
			rn := []rune(plain)
			for i := 0; i <= len(rn); i++ {
				var sb strings.Builder
				sb.WriteString(wht)
				sb.WriteString(string(rn[:i]))
				sb.WriteString(rst)
				rem := len(rn) - i
				if rem > 0 {
					for j := 0; j < rem; j++ {
						t := float64(j) / float64(rem)
						sb.WriteString(ansiFg(lerpRGB(col4, col6, t)))
						sb.WriteByte(animateCharset[rand.Intn(len(animateCharset))])
					}
					sb.WriteString(rst)
				}
				fmt.Fprint(termFile, "\r"+sb.String())
				if i < len(rn) {
					time.Sleep(speed)
				}
			}
			fmt.Fprintf(termFile, "\r  %s\n", styled)
		}

		scrambleRawLine := func(text string, speed time.Duration) {
			if !isAnim || text == "" {
				fmt.Fprintln(w, text)
				return
			}
			rn := []rune(text)
			for i := 0; i <= len(rn); i++ {
				var sb strings.Builder
				sb.WriteString(wht)
				sb.WriteString(string(rn[:i]))
				sb.WriteString(rst)
				rem := len(rn) - i
				if rem > 0 {
					for j := 0; j < rem; j++ {
						t := float64(j) / float64(rem)
						sb.WriteString(ansiFg(lerpRGB(col4, col6, t)))
						sb.WriteByte(animateCharset[rand.Intn(len(animateCharset))])
					}
					sb.WriteString(rst)
				}
				fmt.Fprint(termFile, "\r"+sb.String())
				if i < len(rn) {
					time.Sleep(speed)
				}
			}
			fmt.Fprintln(termFile)
		}

		if cmd != rootCmd {
			if !isAnim {
				defaultHelpFunc(cmd, args)
				return
			}
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			defaultHelpFunc(cmd, args)
			cmd.SetOut(w)
			cmd.SetErr(w)
			lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
			for _, line := range lines {
				scrambleRawLine(line, 1*time.Millisecond)
			}
			return
		}

		if termFile != nil {
			animateBanner(termFile, s)
		} else {
			fmt.Fprintln(w, s.banner.Render("cipherlock  ·  AES-256-GCM  ·  Argon2id  ·  X25519"))
		}
		fmt.Fprintln(w)

		printCmd := func(name, desc string) {
			if isAnim {
				padded := padName(name)
				plain := "  " + padded + " " + desc
				styled := s.cmd.Render(name) + " " + s.desc.Render(desc)
				scrambleLine(plain, styled, 2*time.Millisecond)
			} else {
				fmt.Fprintf(w, "  %s %s\n", s.cmd.Render(name), s.desc.Render(desc))
			}
		}

		printSection := func(title string) {
			fmt.Fprintln(w)
			fmt.Fprintln(w, s.section.Render(title))
			if isAnim {
				time.Sleep(50 * time.Millisecond)
			}
		}

		printSection("Operations:")
		printCmd("encrypt <path>", "Encrypt a file or directory")
		printCmd("decrypt <path>", "Decrypt a file")
		printCmd("rotor <file>", "Re-encrypt with a new password")

		printSection("Themed:")
		printCmd("dial", "Generate X25519 key pair")
		printCmd("tumbler <file>", "Inspect encrypted file metadata")
		printCmd("click <file>", "Verify password and integrity")
		printCmd("bombe <file>", "Verify integrity via checksum")
		printCmd("gate", "Time-gated encrypt/decrypt")

		printSection("Key Management:")
		printCmd("config", "Manage configuration profiles")
		printCmd("show-profile <name>", "Display a configuration profile")

		printSection("Utility:")
		printCmd("bench", "Benchmark Argon2id performance")
		printCmd("shred <path>", "Securely delete files")
		printCmd("completion", "Generate shell completions")
		printCmd("version", "Print version information")

		fmt.Fprintln(w)
		fmt.Fprintln(w, s.section.Render("Flags:"))
		for _, pair := range []struct{ plain, styled string }{
			{"  --in-place  --keep  --backup  --dry-run  --recursive", s.dim.Render("--in-place  --keep  --backup  --dry-run  --recursive")},
			{"  --include <glob>  --exclude <glob>  --quiet  --color1..6", s.dim.Render("--include <glob>  --exclude <glob>  --quiet  --color1..6")},
			{"  'cipherlock <command> --help' for detailed flags", s.dim.Render("'cipherlock <command> --help' for detailed flags")},
		} {
			if isAnim {
				scrambleLine(pair.plain, pair.styled, 2*time.Millisecond)
			} else {
				fmt.Fprintf(w, "  %s\n", pair.styled)
			}
		}
	})
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintf(cmd.OutOrStdout(), "cipherlock %s\n", Version)
		return nil
	},
}

// Execute runs the cipherlock CLI, dispatching to the appropriate
// subcommand (encrypt, decrypt, rekey, completion, config, shred, info).
// It returns an error when the command fails; the root command itself is
// configured to suppress printing usage on errors via SilenceUsage.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(func() {
		quiet.Store(quietFlag)
	})
	rootCmd.PersistentFlags().BoolVar(&inPlace, "in-place", false, "overwrite the source file instead of creating a new one")
	rootCmd.PersistentFlags().BoolVar(&keep, "keep", false, "keep the original file (opposite of --in-place)")
	rootCmd.PersistentFlags().BoolVar(&backup, "backup", false, "save original with .bak extension before overwriting")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "simulate the operation without writing any files")
	rootCmd.PersistentFlags().BoolVar(&recursive, "recursive", false, "process directories recursively")
	rootCmd.PersistentFlags().StringVar(&include, "include", "", "only process files matching this glob pattern")
	rootCmd.PersistentFlags().StringVar(&exclude, "exclude", "", "exclude files matching this glob pattern")
	rootCmd.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "suppress progress output")
	rootCmd.PersistentFlags().StringVar(&color1, "color1", "#e3342f", "color for errors")
	rootCmd.PersistentFlags().StringVar(&color2, "color2", "#22808c", "color for text/labels")
	rootCmd.PersistentFlags().StringVar(&color3, "color3", "#ffffff", "color for spinner chars")
	rootCmd.PersistentFlags().StringVar(&color4, "color4", "#32b8c6", "color for filled bar")
	rootCmd.PersistentFlags().StringVar(&color5, "color5", "#d6d5d4", "color for empty bar")
	rootCmd.PersistentFlags().StringVar(&color6, "color6", "#0f3639", "color for gradient B")
	rootCmd.AddCommand(versionCmd)
}
