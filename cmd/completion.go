package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: fmt.Sprintf(`To load completions:

Bash:
  $ source <(%[1]s completion bash)
  $ %[1]s completion bash > /usr/local/etc/bash_completion.d/%[1]s

Zsh:
  $ source <(%[1]s completion zsh)
  $ %[1]s completion zsh > "${fpath[1]}/_%[1]s"

Fish:
  $ %[1]s completion fish > ~/.config/fish/completions/%[1]s.fish

PowerShell:
  PS> %[1]s completion powershell > %[1]s.ps1
`, rootCmd.Use),
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletion(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %s", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
