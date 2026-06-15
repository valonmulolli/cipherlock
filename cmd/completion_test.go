package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestCompletionShells(t *testing.T) {
	shells := []struct {
		name string
		args []string
	}{
		{"bash", []string{"bash"}},
		{"zsh", []string{"zsh"}},
		{"fish", []string{"fish"}},
		{"powershell", []string{"powershell"}},
	}

	for _, s := range shells {
		t.Run(s.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}

			oldStdout := os.Stdout
			os.Stdout = w

			err = completionCmd.RunE(completionCmd, s.args)

			w.Close()
			os.Stdout = oldStdout

			if err != nil {
				t.Fatalf("completion %s failed: %v", s.name, err)
			}

			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				t.Fatal(err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s completion output is empty", s.name)
			}
		})
	}
}

func TestCompletionUnsupportedShell(t *testing.T) {
	if err := completionCmd.RunE(completionCmd, []string{"unsupported"}); err == nil {
		t.Fatal("expected error for unsupported shell, got nil")
	}
}
