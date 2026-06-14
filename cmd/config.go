package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration profiles",
}

var setProfileCmd = &cobra.Command{
	Use:   "set-profile <name>",
	Short: "Create or update a configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		time, _ := cmd.Flags().GetUint32("time")
		memory, _ := cmd.Flags().GetUint32("memory")
		threads, _ := cmd.Flags().GetUint8("threads")
		checksum, _ := cmd.Flags().GetBool("checksum")

		profile := cipherlock.Profile{
			Time:     time,
			Memory:   memory,
			Threads:  threads,
			Checksum: checksum,
		}

		store, err := loadProfileStore()
		if err != nil {
			return err
		}

		store.Profiles[name] = profile
		if err := saveProfileStore(store); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "profile %q saved\n", name)
		return nil
	},
}

var listProfilesCmd = &cobra.Command{
	Use:   "list-profiles",
	Short: "List all saved configuration profiles",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadProfileStore()
		if err != nil {
			return err
		}

		if len(store.Profiles) == 0 {
			fmt.Println("no profiles configured")
			return nil
		}

		for name, p := range store.Profiles {
			fmt.Printf("%s:\n", name)
			fmt.Printf("  time:     %d\n", p.Time)
			fmt.Printf("  memory:   %d KB\n", p.Memory)
			fmt.Printf("  threads:  %d\n", p.Threads)
			fmt.Printf("  checksum: %t\n", p.Checksum)
		}
		return nil
	},
}

var removeProfileCmd = &cobra.Command{
	Use:   "remove-profile <name>",
	Short: "Remove a configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		store, err := loadProfileStore()
		if err != nil {
			return err
		}

		if _, ok := store.Profiles[name]; !ok {
			return fmt.Errorf("profile %q not found", name)
		}

		delete(store.Profiles, name)
		if err := saveProfileStore(store); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "profile %q removed\n", name)
		return nil
	},
}

type profileStore struct {
	Profiles map[string]cipherlock.Profile `json:"profiles"`
}

func profilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "cipherlock")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles.json"), nil
}

func loadProfileStore() (*profileStore, error) {
	path, err := profilePath()
	if err != nil {
		return &profileStore{Profiles: make(map[string]cipherlock.Profile)}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &profileStore{Profiles: make(map[string]cipherlock.Profile)}, nil
		}
		return nil, err
	}

	var store profileStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Profiles == nil {
		store.Profiles = make(map[string]cipherlock.Profile)
	}
	return &store, nil
}

func saveProfileStore(store *profileStore) error {
	path, err := profilePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	// Write to a tempfile in the same directory then rename atomically,
	// so a concurrent reader never sees a partially-written file.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profiles-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Chmod(path, 0600)
}

func lookupProfile(name string) (*cipherlock.Profile, error) {
	store, err := loadProfileStore()
	if err != nil {
		return nil, err
	}
	p, ok := store.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	return &p, nil
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(setProfileCmd)
	configCmd.AddCommand(listProfilesCmd)
	configCmd.AddCommand(removeProfileCmd)

	setProfileCmd.Flags().Uint32("time", 3, "Argon2id time parameter")
	setProfileCmd.Flags().Uint32("memory", 65536, "Argon2id memory parameter in KB")
	setProfileCmd.Flags().Uint8("threads", 4, "Argon2id parallelism")
	setProfileCmd.Flags().Bool("checksum", true, "enable checksum verification")
}
