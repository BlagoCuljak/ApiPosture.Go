package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// Severity icons and colors
var severityConfig = map[models.Severity]struct {
	Color *color.Color
	Icon  string
}{
	models.SeverityCritical: {color.New(color.FgRed, color.Bold), "!!"},
	models.SeverityHigh:     {color.New(color.FgRed), "!"},
	models.SeverityMedium:   {color.New(color.FgYellow), "*"},
	models.SeverityLow:      {color.New(color.FgBlue), "-"},
	models.SeverityInfo:     {color.New(color.Faint), "i"},
}

// Classification colors
var classificationColors = map[models.SecurityClassification]*color.Color{
	models.ClassificationPublic:           color.New(color.FgRed),
	models.ClassificationAuthenticated:    color.New(color.FgGreen),
	models.ClassificationRoleRestricted:   color.New(color.FgCyan),
	models.ClassificationPolicyRestricted: color.New(color.FgMagenta),
}

// TerminalFormatter formats output for terminal display.
type TerminalFormatter struct {
	opts FormatterOptions
}

// NewTerminalFormatter creates a new TerminalFormatter.
func NewTerminalFormatter(opts FormatterOptions) *TerminalFormatter {
	if opts.NoColor {
		color.NoColor = true
	}
	return &TerminalFormatter{opts: opts}
}

// Format formats the scan result as a string.
func (f *TerminalFormatter) Format(result *models.ScanResult) (string, error) {
	var sb strings.Builder
	if err := f.Write(result, &sb); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// Write writes the formatted result to a writer.
func (f *TerminalFormatter) Write(result *models.ScanResult, w io.Writer) error {
	f.writeHeader(result, w)
	f.writeSummary(result, w)

	if len(result.ActiveFindings()) > 0 {
		f.writeFindings(result, w)
	}

	if len(result.Endpoints) > 0 {
		f.writeEndpoints(result, w)
	}

	f.writeFooter(result, w)

	return nil
}

func (f *TerminalFormatter) writeHeader(result *models.ScanResult, w io.Writer) {
	bold := color.New(color.Bold)

	fmt.Fprintln(w, strings.Repeat("─", 60))
	bold.Fprintln(w, "ApiPosture Security Scan")
	fmt.Fprintf(w, "Path: %s\n", result.ScanPath)
	fmt.Fprintln(w, strings.Repeat("─", 60))
	fmt.Fprintln(w)
}

func (f *TerminalFormatter) writeSummary(result *models.ScanResult, w io.Writer) {
	bold := color.New(color.Bold)
	summary := result.SeveritySummary()

	// Build findings summary
	var parts []string
	if summary[models.SeverityCritical] > 0 {
		parts = append(parts, severityConfig[models.SeverityCritical].Color.Sprintf("%d critical", summary[models.SeverityCritical]))
	}
	if summary[models.SeverityHigh] > 0 {
		parts = append(parts, severityConfig[models.SeverityHigh].Color.Sprintf("%d high", summary[models.SeverityHigh]))
	}
	if summary[models.SeverityMedium] > 0 {
		parts = append(parts, severityConfig[models.SeverityMedium].Color.Sprintf("%d medium", summary[models.SeverityMedium]))
	}
	if summary[models.SeverityLow] > 0 {
		parts = append(parts, severityConfig[models.SeverityLow].Color.Sprintf("%d low", summary[models.SeverityLow]))
	}
	if summary[models.SeverityInfo] > 0 {
		parts = append(parts, severityConfig[models.SeverityInfo].Color.Sprintf("%d info", summary[models.SeverityInfo]))
	}

	var findingsStr string
	if len(parts) > 0 {
		findingsStr = strings.Join(parts, ", ")
	} else {
		findingsStr = color.GreenString("No findings")
	}

	// Frameworks
	frameworks := make([]string, 0, len(result.FrameworksDetected))
	for fw := range result.FrameworksDetected {
		frameworks = append(frameworks, string(fw))
	}
	frameworksStr := "None"
	if len(frameworks) > 0 {
		frameworksStr = strings.Join(frameworks, ", ")
	}

	bold.Fprint(w, "Files scanned: ")
	fmt.Fprintln(w, len(result.FilesScanned))

	bold.Fprint(w, "Frameworks: ")
	fmt.Fprintln(w, frameworksStr)

	bold.Fprint(w, "Endpoints: ")
	fmt.Fprintln(w, len(result.Endpoints))

	bold.Fprint(w, "Findings: ")
	fmt.Fprintln(w, findingsStr)

	if len(result.ParseErrors) > 0 {
		color.Yellow("Parse errors: %d\n", len(result.ParseErrors))
	}

	fmt.Fprintln(w)
}

func (f *TerminalFormatter) writeFindings(result *models.ScanResult, w io.Writer) {
	bold := color.New(color.Bold)

	bold.Fprintln(w, "Security Findings")
	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Header
	fmt.Fprintf(w, "%-4s %-8s %-25s %-8s %s\n", "Sev", "Rule", "Route", "Method", "Message")
	fmt.Fprintln(w, strings.Repeat("-", 80))

	for _, finding := range result.ActiveFindings() {
		cfg := severityConfig[finding.Severity]

		icon := cfg.Icon
		if f.opts.NoIcons {
			icon = strings.ToUpper(string(finding.Severity)[0:1])
		}

		sevStr := cfg.Color.Sprint(icon)

		route := finding.Endpoint.FullRoute()
		if len(route) > 23 {
			route = route[:20] + "..."
		}

		methods := finding.Endpoint.DisplayMethods()
		if len(methods) > 6 {
			methods = methods[:6] + ".."
		}

		message := finding.Message
		if len(message) > 40 {
			message = message[:37] + "..."
		}

		fmt.Fprintf(w, "%-4s %-8s %-25s %-8s %s\n",
			sevStr, finding.RuleID, route, methods, message)
	}

	fmt.Fprintln(w)
}

func (f *TerminalFormatter) writeEndpoints(result *models.ScanResult, w io.Writer) {
	bold := color.New(color.Bold)

	bold.Fprintln(w, "Discovered Endpoints")
	fmt.Fprintln(w, strings.Repeat("─", 60))

	// Header
	fmt.Fprintf(w, "%-30s %-10s %-15s %-10s %s\n", "Route", "Method", "Classification", "Framework", "Function")
	fmt.Fprintln(w, strings.Repeat("-", 90))

	for _, endpoint := range result.Endpoints {
		route := endpoint.FullRoute()
		if len(route) > 28 {
			route = route[:25] + "..."
		}

		methods := endpoint.DisplayMethods()
		if len(methods) > 8 {
			methods = methods[:8] + ".."
		}

		classColor := classificationColors[endpoint.Classification]
		if classColor == nil {
			classColor = color.New(color.Reset)
		}

		funcName := endpoint.FunctionName
		if len(funcName) > 20 {
			funcName = funcName[:17] + "..."
		}

		fmt.Fprintf(w, "%-30s %-10s %s %-10s %s\n",
			route, methods,
			classColor.Sprintf("%-15s", endpoint.Classification),
			endpoint.Framework, funcName)
	}

	fmt.Fprintln(w)
}

func (f *TerminalFormatter) writeFooter(result *models.ScanResult, w io.Writer) {
	faint := color.New(color.Faint)
	faint.Fprintf(w, "Scan completed in %dms\n", result.DurationMs())
}
