// Package output provides output formatters for scan results.
package output

import (
	"io"

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

// Formatter is the interface for output formatters.
type Formatter interface {
	// Format formats the scan result as a string.
	Format(result *models.ScanResult) (string, error)

	// Write writes the formatted result to a writer.
	Write(result *models.ScanResult, w io.Writer) error
}
