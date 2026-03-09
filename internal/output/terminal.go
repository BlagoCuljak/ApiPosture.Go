package output

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/fatih/color"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

const panelWidth = 72

// ansiEscape matches ANSI escape codes for visual-width calculations.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// visibleLen returns the rune count of s with ANSI escape codes stripped.
func visibleLen(s string) int {
	return len([]rune(ansiEscape.ReplaceAllString(s, "")))
}

// truncate shortens s to max runes, appending "..." if needed.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

// wrapText wraps text to maxWidth characters per line.
func wrapText(text string, maxWidth int) []string {
	if maxWidth <= 0 || len(text) <= maxWidth {
		return []string{text}
	}
	var lines []string
	words := strings.Fields(text)
	var cur strings.Builder
	for _, word := range words {
		if cur.Len() > 0 && cur.Len()+1+len(word) > maxWidth {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(word)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

// padVisual right-pads s to width columns, accounting for ANSI escape codes.
func padVisual(s string, width int) string {
	vis := visibleLen(s)
	if vis >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vis)
}

// kvRow is a key/value pair for the summary table.
type kvRow struct{ k, v string }

// Severity icons (emoji) and text fallbacks (matching .NET AccessibilityHelper).
var severityIcons = map[models.Severity]string{
	models.SeverityCritical: "❌",
	models.SeverityHigh:     "⚠️",
	models.SeverityMedium:   "⚡",
	models.SeverityLow:      "ℹ️",
	models.SeverityInfo:     "ℹ️",
}

var severityLabels = map[models.Severity]string{
	models.SeverityCritical: "[CRIT]",
	models.SeverityHigh:     "[HIGH]",
	models.SeverityMedium:   "[MED]",
	models.SeverityLow:      "[LOW]",
	models.SeverityInfo:     "[INFO]",
}

var severityConfig = map[models.Severity]struct {
	Color *color.Color
	Icon  string
}{
	models.SeverityCritical: {color.New(color.FgRed, color.Bold), severityIcons[models.SeverityCritical]},
	models.SeverityHigh:     {color.New(color.FgRed), severityIcons[models.SeverityHigh]},
	models.SeverityMedium:   {color.New(color.FgYellow), severityIcons[models.SeverityMedium]},
	models.SeverityLow:      {color.New(color.FgBlue), severityIcons[models.SeverityLow]},
	models.SeverityInfo:     {color.New(color.Faint), severityIcons[models.SeverityInfo]},
}

// Classification icons and colors (matching .NET AccessibilityHelper).
var classificationIcons = map[models.SecurityClassification]string{
	models.ClassificationPublic:           "🔓",
	models.ClassificationAuthenticated:    "🔐",
	models.ClassificationRoleRestricted:   "🔒",
	models.ClassificationPolicyRestricted: "🛡️",
}

var classificationLabels = map[models.SecurityClassification]string{
	models.ClassificationPublic:           "[PUBLIC]",
	models.ClassificationAuthenticated:    "[AUTH]",
	models.ClassificationRoleRestricted:   "[ROLE]",
	models.ClassificationPolicyRestricted: "[POLICY]",
}

// classificationColors matches .NET: public=red, auth=yellow, role=green, policy=blue.
var classificationColors = map[models.SecurityClassification]*color.Color{
	models.ClassificationPublic:           color.New(color.FgRed),
	models.ClassificationAuthenticated:    color.New(color.FgYellow),
	models.ClassificationRoleRestricted:   color.New(color.FgGreen),
	models.ClassificationPolicyRestricted: color.New(color.FgBlue),
}

// TerminalFormatter formats output for terminal display.
type TerminalFormatter struct {
	opts FormatterOptions
}

// NewTerminalFormatter creates a new TerminalFormatter.
func NewTerminalFormatter(opts FormatterOptions) *TerminalFormatter {
	opts.ApplyEnvironmentDefaults()
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
// Output order matches the .NET version:
//  1. Header rule
//  2. Findings panels (rendered first so they appear at top when scrolling up)
//  3. Scroll hint (if findings exist)
//  4. Summary table
//  5. Severity breakdown chart
//  6. Endpoints table (at bottom, visible immediately after scan)
//  7. "No security findings!" if clean
func (f *TerminalFormatter) Write(result *models.ScanResult, w io.Writer) error {
	fmt.Fprintln(w)
	f.writeHeader(w)

	findings := result.ActiveFindings()

	// Findings FIRST — so they appear at top when scrolling up.
	if len(findings) > 0 {
		f.writeFindings(findings, w)
		f.writeScrollHint(w)
	}

	// Summary table.
	f.writeSummaryTable(result, w)

	// Severity breakdown.
	f.writeSeverityChart(result, w)

	// Endpoints table at BOTTOM — visible immediately after scan.
	if len(result.Endpoints) > 0 {
		fmt.Fprintln(w)
		f.writeEndpointsTable(result, w)
	}

	// Final status.
	if len(findings) == 0 {
		fmt.Fprintln(w)
		color.New(color.FgGreen).Fprintln(w, "No security findings!")
	}

	fmt.Fprintln(w)
	f.writeFooter(result, w)
	return nil
}

func (f *TerminalFormatter) writeHeader(w io.Writer) {
	bold := color.New(color.Bold)
	writeRule(w, bold.Sprint("ApiPosture Security Scan"), 60)
	fmt.Fprintln(w)
}

func (f *TerminalFormatter) writeScrollHint(w io.Writer) {
	faint := color.New(color.Faint)
	fmt.Fprintln(w)
	writeRule(w, faint.Sprint("^^^^ Scroll up for finding details ^^^^"), 70)
	fmt.Fprintln(w)
}

func (f *TerminalFormatter) writeFindings(findings []*models.Finding, w io.Writer) {
	bold := color.New(color.Bold)
	writeRule(w, bold.Sprintf("Security Findings (%d)", len(findings)), 70)
	fmt.Fprintln(w)

	for _, finding := range findings {
		f.writeFindingPanel(finding, w)
		fmt.Fprintln(w)
	}
}

func (f *TerminalFormatter) writeFindingPanel(finding *models.Finding, w io.Writer) {
	cfg := severityConfig[finding.Severity]

	var icon string
	if f.opts.NoIcons {
		icon = severityLabels[finding.Severity]
	} else {
		icon = cfg.Icon
	}

	headerText := fmt.Sprintf("%s [%s] %s (%s)", icon, finding.RuleID, finding.RuleName, finding.Severity)
	header := cfg.Color.Sprint(headerText)

	innerWidth := panelWidth - 4 // "│ " + " │"

	var lines []string
	lines = append(lines, fmt.Sprintf("Route:    %s", finding.Endpoint.FullRoute()))
	lines = append(lines, fmt.Sprintf("Location: %s", finding.Endpoint.ShortLocation()))
	lines = append(lines, "")
	lines = append(lines, wrapText(finding.Message, innerWidth)...)
	if finding.Recommendation != "" {
		lines = append(lines, "")
		prefix := "Recommendation: "
		wrapped := wrapText(finding.Recommendation, innerWidth-len(prefix))
		for i, l := range wrapped {
			if i == 0 {
				lines = append(lines, prefix+l)
			} else {
				lines = append(lines, strings.Repeat(" ", len(prefix))+l)
			}
		}
	}

	writePanel(w, header, lines, panelWidth)
}

func (f *TerminalFormatter) writeSummaryTable(result *models.ScanResult, w io.Writer) {
	summary := result.SeveritySummary()
	active := result.ActiveFindings()
	suppressed := result.SuppressedFindings()

	var parts []string
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		if summary[sev] > 0 {
			parts = append(parts, severityConfig[sev].Color.Sprintf("%d %s", summary[sev], sev))
		}
	}
	findingsVal := color.GreenString("None")
	if len(parts) > 0 {
		findingsVal = strings.Join(parts, ", ")
	}
	if len(suppressed) > 0 {
		findingsVal += color.New(color.Faint).Sprintf(" (%d suppressed)", len(suppressed))
	}

	frameworks := make([]string, 0, len(result.FrameworksDetected))
	for fw := range result.FrameworksDetected {
		frameworks = append(frameworks, string(fw))
	}
	fwStr := "None"
	if len(frameworks) > 0 {
		fwStr = strings.Join(frameworks, ", ")
	}

	rows := []kvRow{
		{"Scanned Path", result.ScanPath},
		{"Files Scanned", fmt.Sprintf("%d", len(result.FilesScanned))},
		{"Parse Errors", fmt.Sprintf("%d", len(result.ParseErrors))},
		{"Frameworks", fwStr},
		{"Total Endpoints", fmt.Sprintf("%d", len(result.Endpoints))},
		{"Total Findings", fmt.Sprintf("%d (active: %d)", len(active)+len(suppressed), len(active))},
		{"Security Findings", findingsVal},
		{"Scan Duration", fmt.Sprintf("%dms", result.DurationMs())},
	}

	keyW := len("Metric")
	valW := len("Value")
	for _, r := range rows {
		if len(r.k) > keyW {
			keyW = len(r.k)
		}
		if vl := visibleLen(r.v); vl > valW {
			valW = vl
		}
	}

	write2ColTable(w, "Metric", "Value", keyW, valW, rows)
}

func (f *TerminalFormatter) writeSeverityChart(result *models.ScanResult, w io.Writer) {
	summary := result.SeveritySummary()

	maxCount := 0
	for _, c := range summary {
		if c > maxCount {
			maxCount = c
		}
	}
	if maxCount == 0 {
		return
	}

	fmt.Fprintln(w)

	const barMax = 20
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		count := summary[sev]
		if count == 0 {
			continue
		}
		cfg := severityConfig[sev]
		var icon string
		if f.opts.NoIcons {
			icon = fmt.Sprintf("%-6s", severityLabels[sev])
		} else {
			icon = cfg.Icon
		}
		barLen := count * barMax / maxCount
		if barLen < 1 {
			barLen = 1
		}
		bar := cfg.Color.Sprint(strings.Repeat("█", barLen))
		fmt.Fprintf(w, "  %s  %-10s %s  %d\n", icon, sev, bar, count)
	}
}

func (f *TerminalFormatter) writeEndpointsTable(result *models.ScanResult, w io.Writer) {
	bold := color.New(color.Bold)
	writeRule(w, bold.Sprint("Discovered Endpoints"), 70)
	fmt.Fprintln(w)

	type epRow struct {
		route     string
		methods   string
		classDisp string // may contain ANSI codes
		classVisW int
		framework string
		function  string
	}

	var rows []epRow
	for _, ep := range result.Endpoints {
		route := truncate(ep.FullRoute(), 35)
		methods := truncate(ep.DisplayMethods(), 12)

		var classText string
		if f.opts.NoIcons {
			classText = classificationLabels[ep.Classification] + " " + string(ep.Classification)
		} else {
			classText = classificationIcons[ep.Classification] + " " + string(ep.Classification)
		}
		cl := classificationColors[ep.Classification]
		if cl == nil {
			cl = color.New(color.Reset)
		}
		classDisp := cl.Sprint(classText)

		rows = append(rows, epRow{
			route:     route,
			methods:   methods,
			classDisp: classDisp,
			classVisW: visibleLen(classDisp),
			framework: truncate(string(ep.Framework), 10),
			function:  truncate(ep.FunctionName, 20),
		})
	}

	// Compute column widths.
	rW := len("Route")
	mW := len("Methods")
	cW := len("Classification")
	fwW := len("Framework")
	fnW := len("Function")
	for _, r := range rows {
		if n := visibleLen(r.route); n > rW {
			rW = n
		}
		if n := visibleLen(r.methods); n > mW {
			mW = n
		}
		if r.classVisW > cW {
			cW = r.classVisW
		}
		if n := len(r.framework); n > fwW {
			fwW = n
		}
		if n := len(r.function); n > fnW {
			fnW = n
		}
	}
	// Extra width for emoji wide characters in classification column.
	if !f.opts.NoIcons {
		cW++
	}

	borderRow := func(tl, join, tr string) string {
		return tl +
			strings.Repeat("─", rW+2) + join +
			strings.Repeat("─", mW+2) + join +
			strings.Repeat("─", cW+2) + join +
			strings.Repeat("─", fwW+2) + join +
			strings.Repeat("─", fnW+2) + tr
	}

	fmt.Fprintln(w, borderRow("╭", "┬", "╮"))
	fmt.Fprintf(w, "│ %-*s │ %-*s │ %-*s │ %-*s │ %-*s │\n",
		rW, "Route", mW, "Methods", cW, "Classification", fwW, "Framework", fnW, "Function")
	fmt.Fprintln(w, borderRow("├", "┼", "┤"))
	for _, r := range rows {
		fmt.Fprintf(w, "│ %-*s │ %-*s │ %s │ %-*s │ %-*s │\n",
			rW, r.route,
			mW, r.methods,
			padVisual(r.classDisp, cW),
			fwW, r.framework,
			fnW, r.function,
		)
	}
	fmt.Fprintln(w, borderRow("╰", "┴", "╯"))
}

func (f *TerminalFormatter) writeFooter(result *models.ScanResult, w io.Writer) {
	color.New(color.Faint).Fprintf(w, "Scan completed in %dms\n", result.DurationMs())
}

// writeRule writes a centered horizontal rule with optional title text.
func writeRule(w io.Writer, title string, width int) {
	vis := visibleLen(title)
	if vis == 0 {
		fmt.Fprintln(w, strings.Repeat("─", width))
		return
	}
	inner := " " + title + " "
	innerVis := 2 + vis
	dashes := width - innerVis
	if dashes < 2 {
		fmt.Fprintln(w, inner)
		return
	}
	left := dashes / 2
	right := dashes - left
	fmt.Fprintf(w, "%s%s%s\n", strings.Repeat("─", left), inner, strings.Repeat("─", right))
}

// writePanel renders a rounded box panel with a colored header and content lines.
func writePanel(w io.Writer, header string, lines []string, width int) {
	inner := width - 2      // subtract ╭ and ╮
	contentWidth := inner - 2 // subtract spaces: "│ " + " │"

	// Top: ╭─ header ───...───╮
	headerVis := visibleLen(header)
	used := 2 + headerVis + 1 // "─ " + header + " "
	remaining := inner - used
	if remaining < 0 {
		remaining = 0
	}
	fmt.Fprintf(w, "╭─ %s %s╮\n", header, strings.Repeat("─", remaining))

	// Content lines.
	for _, line := range lines {
		padding := contentWidth - visibleLen(line)
		if padding < 0 {
			padding = 0
		}
		fmt.Fprintf(w, "│ %s%s │\n", line, strings.Repeat(" ", padding))
	}

	// Bottom: ╰──...──╯
	fmt.Fprintf(w, "╰%s╯\n", strings.Repeat("─", inner))
}

// write2ColTable renders a rounded 2-column key/value table.
func write2ColTable(w io.Writer, h1, h2 string, col1W, col2W int, rows []kvRow) {
	if len(h1) > col1W {
		col1W = len(h1)
	}
	if len(h2) > col2W {
		col2W = len(h2)
	}

	hbar := func(tl, mid, tr string) string {
		return tl + strings.Repeat("─", col1W+2) + mid + strings.Repeat("─", col2W+2) + tr
	}

	fmt.Fprintln(w, hbar("╭", "┬", "╮"))
	fmt.Fprintf(w, "│ %-*s │ %-*s │\n", col1W, h1, col2W, h2)
	fmt.Fprintln(w, hbar("├", "┼", "┤"))
	for _, r := range rows {
		fmt.Fprintf(w, "│ %-*s │ %s │\n", col1W, r.k, padVisual(r.v, col2W))
	}
	fmt.Fprintln(w, hbar("╰", "┴", "╯"))
}
