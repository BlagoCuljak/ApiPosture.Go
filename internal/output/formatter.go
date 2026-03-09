// Package output provides output formatters for scan results.
package output

import (
	"io"
	"os"
	"runtime"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// FormatterOptions contains options for output formatters.
type FormatterOptions struct {
	// NoColor disables colored output.
	NoColor bool

	// NoIcons disables icons in output.
	NoIcons bool

	// GroupBy groups results by field (file, classification, rule, framework).
	GroupBy string

	// Verbose enables verbose output.
	Verbose bool
}

// ApplyEnvironmentDefaults auto-detects NO_COLOR, TTY redirect, and
// Windows legacy console to set NoColor/NoIcons when not already forced.
func (o *FormatterOptions) ApplyEnvironmentDefaults() {
	if !o.NoColor {
		// NO_COLOR environment variable (https://no-color.org/)
		if noColor := os.Getenv("NO_COLOR"); noColor != "" {
			o.NoColor = true
		}
		// Disable colors when stdout is not a TTY (redirected output).
		// fatih/color also checks this, but we set it explicitly so NoIcons
		// logic below can rely on a consistent state.
		if fileInfo, err := os.Stdout.Stat(); err == nil {
			if fileInfo.Mode()&os.ModeCharDevice == 0 {
				o.NoColor = true
			}
		}
	}
	if !o.NoIcons {
		// Auto-detect: disable icons on Windows legacy consoles (cmd.exe,
		// PowerShell) which cannot render emoji. Windows Terminal sets
		// WT_SESSION and handles emoji fine.
		if runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" {
			o.NoIcons = true
		}
	}
}

// Formatter is the interface for output formatters.
type Formatter interface {
	// Format formats the scan result as a string.
	Format(result *models.ScanResult) (string, error)

	// Write writes the formatted result to a writer.
	Write(result *models.ScanResult, w io.Writer) error
}
