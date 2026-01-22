package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/licensing"
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "License management commands",
	Long:  "Commands for managing your ApiPosture license (Pro features).",
}

var licenseStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show license status",
	Run: func(cmd *cobra.Command, args []string) {
		manager := licensing.NewManager()
		status := manager.Status()
		fmt.Println(status)
	},
}

var licenseActivateCmd = &cobra.Command{
	Use:   "activate [key]",
	Short: "Activate a license key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		manager := licensing.NewManager()
		err := manager.Activate(args[0])
		if err != nil {
			fmt.Printf("Activation failed: %v\n", err)
			return
		}
		fmt.Println("License activated successfully!")
	},
}

func init() {
	licenseCmd.AddCommand(licenseStatusCmd)
	licenseCmd.AddCommand(licenseActivateCmd)
}
