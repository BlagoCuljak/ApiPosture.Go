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
	_, _ = fmt.Fprintln(w, "# ApiPosture Security Scan Report")
	_, _ = fmt.Fprintln(w)

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
	_, _ = fmt.Fprintln(w, "## Summary")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "- **Scan Path:** `%s`\n", result.ScanPath)
	_, _ = fmt.Fprintf(w, "- **Files Scanned:** %d\n", len(result.FilesScanned))

	// Frameworks
	frameworks := make([]string, 0, len(result.FrameworksDetected))
	for fw := range result.FrameworksDetected {
		frameworks = append(frameworks, string(fw))
	}
	if len(frameworks) > 0 {
		_, _ = fmt.Fprintf(w, "- **Frameworks Detected:** %s\n", strings.Join(frameworks, ", "))
	} else {
		_, _ = fmt.Fprintln(w, "- **Frameworks Detected:** None")
	}

	_, _ = fmt.Fprintf(w, "- **Endpoints Found:** %d\n", len(result.Endpoints))
	_, _ = fmt.Fprintf(w, "- **Security Findings:** %d\n", len(result.ActiveFindings()))

	// Severity breakdown
	summary := result.SeveritySummary()
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "### Findings by Severity")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "| Severity | Count |\n")
	_, _ = fmt.Fprintf(w, "|----------|-------|\n")
	_, _ = fmt.Fprintf(w, "| Critical | %d |\n", summary[models.SeverityCritical])
	_, _ = fmt.Fprintf(w, "| High | %d |\n", summary[models.SeverityHigh])
	_, _ = fmt.Fprintf(w, "| Medium | %d |\n", summary[models.SeverityMedium])
	_, _ = fmt.Fprintf(w, "| Low | %d |\n", summary[models.SeverityLow])
	_, _ = fmt.Fprintf(w, "| Info | %d |\n", summary[models.SeverityInfo])
	_, _ = fmt.Fprintln(w)
}

func (f *MarkdownFormatter) writeFindings(result *models.ScanResult, w io.Writer) {
	_, _ = fmt.Fprintln(w, "## Security Findings")
	_, _ = fmt.Fprintln(w)

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
		sevStr := string(sev)
		if len(sevStr) > 0 {
			sevStr = strings.ToUpper(sevStr[:1]) + sevStr[1:]
		}
		_, _ = fmt.Fprintf(w, "### %s %s Severity\n\n", emoji, sevStr)

		for _, finding := range findings {
			_, _ = fmt.Fprintf(w, "#### %s: %s\n\n", finding.RuleID, finding.RuleName)
			_, _ = fmt.Fprintf(w, "- **Route:** `%s`\n", finding.Endpoint.FullRoute())
			_, _ = fmt.Fprintf(w, "- **Methods:** %s\n", finding.Endpoint.DisplayMethods())
			_, _ = fmt.Fprintf(w, "- **Location:** `%s`\n", finding.Location())
			_, _ = fmt.Fprintf(w, "- **Message:** %s\n", finding.Message)
			if finding.Recommendation != "" {
				_, _ = fmt.Fprintf(w, "- **Recommendation:** %s\n", finding.Recommendation)
			}
			_, _ = fmt.Fprintln(w)
		}
	}
}

func (f *MarkdownFormatter) writeEndpoints(result *models.ScanResult, w io.Writer) {
	_, _ = fmt.Fprintln(w, "## Discovered Endpoints")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "| Route | Methods | Classification | Framework | Function | Location |")
	_, _ = fmt.Fprintln(w, "|-------|---------|----------------|-----------|----------|----------|")

	for _, endpoint := range result.Endpoints {
		_, _ = fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | %s |\n",
			endpoint.FullRoute(),
			endpoint.DisplayMethods(),
			endpoint.Classification,
			endpoint.Framework,
			endpoint.FunctionName,
			endpoint.ShortLocation())
	}

	_, _ = fmt.Fprintln(w)
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
