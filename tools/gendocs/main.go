// Program gendocs generates markdown CLI documentation from the cobra command tree.
//
// Usage:
//
//	go run tools/gendocs/main.go
//
// It produces one .md file per command under docs/cli/.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/valonmulolli/cipherlock/cmd"
)

func disableAutoTag(c *cobra.Command) {
	c.DisableAutoGenTag = true
	for _, child := range c.Commands() {
		disableAutoTag(child)
	}
}

func main() {
	if err := os.MkdirAll("docs/cli", 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	rootCmd := cmd.RootCommand()
	disableAutoTag(rootCmd)

	if err := doc.GenMarkdownTree(rootCmd, "docs/cli"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("generated docs/cli/ from cobra command tree")
}
