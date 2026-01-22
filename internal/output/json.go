package output

import (
	"encoding/json"
	"io"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// JSONFormatter formats output as JSON.
type JSONFormatter struct {
	opts FormatterOptions
}

// NewJSONFormatter creates a new JSONFormatter.
func NewJSONFormatter(opts FormatterOptions) *JSONFormatter {
	return &JSONFormatter{opts: opts}
}

// Format formats the scan result as a JSON string.
func (f *JSONFormatter) Format(result *models.ScanResult) (string, error) {
	data := result.ToMap()

	var output []byte
	var err error

	if f.opts.Verbose {
		output, err = json.MarshalIndent(data, "", "  ")
	} else {
		output, err = json.MarshalIndent(data, "", "  ")
	}

	if err != nil {
		return "", err
	}

	return string(output), nil
}

// Write writes the formatted result to a writer.
func (f *JSONFormatter) Write(result *models.ScanResult, w io.Writer) error {
	output, err := f.Format(result)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(output))
	return err
}
