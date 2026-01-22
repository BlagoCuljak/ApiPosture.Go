// Package cli contains the Cobra CLI commands for ApiPosture.
package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/BlagoCuljak/ApiPosture.Go/pkg/version"
)

var rootCmd = &cobra.Command{
	Use:   "apiposture",
	Short: "API security inspection tool for Go applications",
	Long: `ApiPosture is a CLI security inspection tool that performs static source-code
analysis to identify authorization misconfigurations and security risks in
Go API frameworks (Gin, Echo, Chi, Fiber, net/http).

Example usage:
  apiposture scan ./path/to/project
  apiposture scan ./path --output json
  apiposture scan ./path --severity high --fail-on high`,
	Version: version.Info(),
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(licenseCmd)
	rootCmd.AddCommand(versionCmd)
}
