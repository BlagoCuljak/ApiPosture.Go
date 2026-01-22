package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// MarkdownFormatter formats output as Markdown.
type MarkdownFormatter struct {
	opts FormatterOptions
}

// NewMarkdownFormatter creates a new MarkdownFormatter.
func NewMarkdownFormatter(opts FormatterOptions) *MarkdownFormatter {
	return &MarkdownFormatter{opts: opts}
}

// Format formats the scan result as a Markdown string.
func (f *MarkdownFormatter) Format(result *models.ScanResult) (string, error) {
	var sb strings.Builder
	if err := f.Write(result, &sb); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// Write writes the formatted result to a writer.
func (f *MarkdownFormatter) Write(result *models.ScanResult, w io.Writer) error {
	// Title
	fmt.Fprintln(w, "# ApiPosture Security Scan Report")
	fmt.Fprintln(w)

	// Summary
	f.writeSummary(result, w)

	// Findings
	if len(result.ActiveFindings()) > 0 {
		f.writeFindings(result, w)
	}

	// Endpoints
	if len(result.Endpoints) > 0 {
		f.writeEndpoints(result, w)
	}

	return nil
}

func (f *MarkdownFormatter) writeSummary(result *models.ScanResult, w io.Writer) {
	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "- **Scan Path:** `%s`\n", result.ScanPath)
	fmt.Fprintf(w, "- **Files Scanned:** %d\n", len(result.FilesScanned))

	// Frameworks
	frameworks := make([]string, 0, len(result.FrameworksDetected))
	for fw := range result.FrameworksDetected {
		frameworks = append(frameworks, string(fw))
	}
	if len(frameworks) > 0 {
		fmt.Fprintf(w, "- **Frameworks Detected:** %s\n", strings.Join(frameworks, ", "))
	} else {
		fmt.Fprintln(w, "- **Frameworks Detected:** None")
	}

	fmt.Fprintf(w, "- **Endpoints Found:** %d\n", len(result.Endpoints))
	fmt.Fprintf(w, "- **Security Findings:** %d\n", len(result.ActiveFindings()))

	// Severity breakdown
	summary := result.SeveritySummary()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "### Findings by Severity")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "|----------|-------|\n")
	fmt.Fprintf(w, "| Critical | %d |\n", summary[models.SeverityCritical])
	fmt.Fprintf(w, "| High | %d |\n", summary[models.SeverityHigh])
	fmt.Fprintf(w, "| Medium | %d |\n", summary[models.SeverityMedium])
	fmt.Fprintf(w, "| Low | %d |\n", summary[models.SeverityLow])
	fmt.Fprintf(w, "| Info | %d |\n", summary[models.SeverityInfo])
	fmt.Fprintln(w)
}

func (f *MarkdownFormatter) writeFindings(result *models.ScanResult, w io.Writer) {
	fmt.Fprintln(w, "## Security Findings")
	fmt.Fprintln(w)

	// Group by severity for better readability
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}

	for _, sev := range severities {
		findings := result.FindingsBySeverity(sev)
		if len(findings) == 0 {
			continue
		}

		emoji := severityEmoji(sev)
		fmt.Fprintf(w, "### %s %s Severity\n\n", emoji, strings.Title(string(sev)))

		for _, finding := range findings {
			fmt.Fprintf(w, "#### %s: %s\n\n", finding.RuleID, finding.RuleName)
			fmt.Fprintf(w, "- **Route:** `%s`\n", finding.Endpoint.FullRoute())
			fmt.Fprintf(w, "- **Methods:** %s\n", finding.Endpoint.DisplayMethods())
			fmt.Fprintf(w, "- **Location:** `%s`\n", finding.Location())
			fmt.Fprintf(w, "- **Message:** %s\n", finding.Message)
			if finding.Recommendation != "" {
				fmt.Fprintf(w, "- **Recommendation:** %s\n", finding.Recommendation)
			}
			fmt.Fprintln(w)
		}
	}
}

func (f *MarkdownFormatter) writeEndpoints(result *models.ScanResult, w io.Writer) {
	fmt.Fprintln(w, "## Discovered Endpoints")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "| Route | Methods | Classification | Framework | Function | Location |")
	fmt.Fprintln(w, "|-------|---------|----------------|-----------|----------|----------|")

	for _, endpoint := range result.Endpoints {
		fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | %s |\n",
			endpoint.FullRoute(),
			endpoint.DisplayMethods(),
			endpoint.Classification,
			endpoint.Framework,
			endpoint.FunctionName,
			endpoint.ShortLocation())
	}

	fmt.Fprintln(w)
}

func severityEmoji(sev models.Severity) string {
	switch sev {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🔵"
	case models.SeverityInfo:
		return "⚪"
	default:
		return "⚪"
	}
}
