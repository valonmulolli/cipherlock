package cmd

import (
	"fmt"
	"os"

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

		profiles, err := cipherlock.LoadProfiles()
		if err != nil {
			return err
		}

		profiles[name] = profile
		if err := cipherlock.SaveProfiles(profiles); err != nil {
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
		profiles, err := cipherlock.LoadProfiles()
		if err != nil {
			return err
		}

		if len(profiles) == 0 {
			fmt.Println("no profiles configured")
			return nil
		}

		for name, p := range profiles {
			fmt.Printf("%s:\n", name)
			fmt.Printf("  time:     %d\n", p.Time)
			fmt.Printf("  memory:   %d KB\n", p.Memory)
			fmt.Printf("  threads:  %d\n", p.Threads)
			fmt.Printf("  checksum: %t\n", p.Checksum)
		}
		return nil
	},
}

var showProfileCmd = &cobra.Command{
	Use:   "show-profile <name>",
	Short: "Display a configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		profiles, err := cipherlock.LoadProfiles()
		if err != nil {
			return err
		}
		profile, ok := profiles[name]
		if !ok {
			return fmt.Errorf("profile %q not found", name)
		}
		fmt.Printf("profile: %s\n", name)
		fmt.Printf("  time:     %d\n", profile.Time)
		fmt.Printf("  memory:   %d KB\n", profile.Memory)
		fmt.Printf("  threads:  %d\n", profile.Threads)
		fmt.Printf("  checksum: %t\n", profile.Checksum)
		return nil
	},
}

var removeProfileCmd = &cobra.Command{
	Use:   "remove-profile <name>",
	Short: "Remove a configuration profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		profiles, err := cipherlock.LoadProfiles()
		if err != nil {
			return err
		}

		if _, ok := profiles[name]; !ok {
			return fmt.Errorf("profile %q not found", name)
		}

		delete(profiles, name)
		if err := cipherlock.SaveProfiles(profiles); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "profile %q removed\n", name)
		return nil
	},
}

func lookupProfile(name string) (*cipherlock.Profile, error) {
	profiles, err := cipherlock.LoadProfiles()
	if err != nil {
		return nil, err
	}
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	return &p, nil
}

func profileNames() []string {
	profiles, err := cipherlock.LoadProfiles()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	return names
}

func init() {
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(showProfileCmd)
	configCmd.AddCommand(setProfileCmd)
	configCmd.AddCommand(listProfilesCmd)
	configCmd.AddCommand(removeProfileCmd)

	setProfileCmd.Flags().Uint32("time", 3, "Argon2id time parameter")
	setProfileCmd.Flags().Uint32("memory", 65536, "Argon2id memory parameter in KB")
	setProfileCmd.Flags().Uint8("threads", 4, "Argon2id parallelism")
	setProfileCmd.Flags().Bool("checksum", true, "enable checksum verification")
}
