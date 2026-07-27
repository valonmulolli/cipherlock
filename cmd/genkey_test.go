package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenKeyOutputFiles(t *testing.T) {
	dir := t.TempDir()

	origDir := genkeyDir
	origPass := genkeyPassphraseFile
	genkeyDir = dir
	genkeyPassphraseFile = ""
	defer func() {
		genkeyDir = origDir
		genkeyPassphraseFile = origPass
	}()

	if err := genKeyCmd.RunE(genKeyCmd, []string{"testkey"}); err != nil {
		t.Fatalf("generate-keypair failed: %v", err)
	}

	identityPath := filepath.Join(dir, "testkey.identity")
	pubPath := filepath.Join(dir, "testkey.pub")

	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		t.Fatal("identity file not created")
	}
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Fatal("public key file not created")
	}

	idData, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(idData) == 0 {
		t.Fatal("identity file is empty")
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubData) == 0 {
		t.Fatal("public key file is empty")
	}
}
