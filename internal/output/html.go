package output

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// HTMLFormatter formats output as an HTML report.
type HTMLFormatter struct {
	opts FormatterOptions
}

// NewHTMLFormatter creates a new HTMLFormatter.
func NewHTMLFormatter(opts FormatterOptions) *HTMLFormatter {
	return &HTMLFormatter{opts: opts}
}

// Format formats the scan result as an HTML string.
func (f *HTMLFormatter) Format(result *models.ScanResult) (string, error) {
	var sb strings.Builder
	if err := f.Write(result, &sb); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// Write writes the formatted result to a writer.
func (f *HTMLFormatter) Write(result *models.ScanResult, w io.Writer) error {
	fmt.Fprintln(w, htmlHead())
	fmt.Fprintln(w, `<body><div class="container">`)
	fmt.Fprintln(w, `<h1>&#x1F6E1;&#xFE0F; ApiPosture Security Scan Report</h1>`)
	fmt.Fprintf(w, `<div class="meta"><strong>Generated:</strong> %s UTC</div>`+"\n", time.Now().UTC().Format("2006-01-02 15:04:05"))

	f.writeSummary(result, w)
	f.writeSeverityBreakdown(result, w)

	if len(result.Endpoints) > 0 {
		f.writeEndpoints(result, w)
	}

	findings := result.ActiveFindings()
	if len(findings) > 0 {
		fmt.Fprintln(w, "<h2>Security Findings</h2>")
		for _, finding := range findings {
			f.writeFinding(finding, w)
		}
	} else {
		fmt.Fprintln(w, "<h2>Security Findings</h2>")
		fmt.Fprintln(w, `<div class="success">&#x2705; No security findings detected!</div>`)
	}

	fmt.Fprintln(w, `</div></body></html>`)
	return nil
}

func (f *HTMLFormatter) writeSummary(result *models.ScanResult, w io.Writer) {
	fmt.Fprintln(w, "<h2>Summary</h2>")
	fmt.Fprintln(w, `<div class="summary-grid">`)

	frameworks := make([]string, 0, len(result.FrameworksDetected))
	for fw := range result.FrameworksDetected {
		frameworks = append(frameworks, string(fw))
	}
	fwStr := "None"
	if len(frameworks) > 0 {
		fwStr = strings.Join(frameworks, ", ")
	}

	summaryCard(w, "Files Scanned", fmt.Sprintf("%d", len(result.FilesScanned)))
	summaryCard(w, "Endpoints Found", fmt.Sprintf("%d", len(result.Endpoints)))
	summaryCard(w, "Frameworks", fwStr)
	summaryCard(w, "Security Findings", fmt.Sprintf("%d", len(result.ActiveFindings())))

	fmt.Fprintln(w, "</div>")
	fmt.Fprintf(w, `<p class="section-subtitle"><strong>Scan Path:</strong> <code>%s</code></p>`+"\n", html.EscapeString(result.ScanPath))
}

func (f *HTMLFormatter) writeSeverityBreakdown(result *models.ScanResult, w io.Writer) {
	summary := result.SeveritySummary()
	total := 0
	for _, c := range summary {
		total += c
	}
	if total == 0 {
		return
	}

	fmt.Fprintln(w, "<h2>Severity Breakdown</h2>")
	fmt.Fprintln(w, `<ul class="severity-list">`)

	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	}
	for _, sev := range severities {
		count := summary[sev]
		if count == 0 {
			continue
		}
		sStr := strings.ToLower(string(sev))
		fmt.Fprintf(w, `<li><span class="severity-badge severity-%s">%s</span> &mdash; %d finding(s)</li>`+"\n",
			html.EscapeString(sStr), html.EscapeString(strings.ToUpper(sStr[:1]) + sStr[1:]), count)
	}
	fmt.Fprintln(w, "</ul>")
}

func (f *HTMLFormatter) writeEndpoints(result *models.ScanResult, w io.Writer) {
	fmt.Fprintln(w, "<h2>Discovered Endpoints</h2>")
	fmt.Fprintln(w, "<table>")
	fmt.Fprintln(w, "  <thead><tr><th>Route</th><th>Methods</th><th>Classification</th><th>Framework</th><th>Function</th><th>Location</th></tr></thead>")
	fmt.Fprintln(w, "  <tbody>")

	for _, ep := range result.Endpoints {
		fmt.Fprintf(w, "    <tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(ep.FullRoute()),
			html.EscapeString(ep.DisplayMethods()),
			html.EscapeString(string(ep.Classification)),
			html.EscapeString(string(ep.Framework)),
			html.EscapeString(ep.FunctionName),
			html.EscapeString(ep.ShortLocation()))
	}

	fmt.Fprintln(w, "  </tbody>")
	fmt.Fprintln(w, "</table>")
}

func (f *HTMLFormatter) writeFinding(finding *models.Finding, w io.Writer) {
	sev := strings.ToLower(string(finding.Severity))
	fmt.Fprintf(w, `<div class="finding %s">`+"\n", html.EscapeString(sev))
	fmt.Fprintf(w, `  <span class="severity-badge severity-%s">%s</span>`+"\n",
		html.EscapeString(sev), html.EscapeString(strings.ToUpper(sev[:1])+sev[1:]))
	fmt.Fprintf(w, "  <h3>[%s] %s</h3>\n", html.EscapeString(finding.RuleID), html.EscapeString(finding.RuleName))
	fmt.Fprintf(w, "  <p><strong>Route:</strong> <code>%s</code></p>\n", html.EscapeString(finding.Endpoint.FullRoute()))
	fmt.Fprintf(w, "  <p><strong>Methods:</strong> %s</p>\n", html.EscapeString(finding.Endpoint.DisplayMethods()))
	fmt.Fprintf(w, "  <p><strong>Location:</strong> <code>%s</code></p>\n", html.EscapeString(finding.Location()))
	fmt.Fprintf(w, "  <p>%s</p>\n", html.EscapeString(finding.Message))
	if finding.Recommendation != "" {
		fmt.Fprintf(w, `  <div class="recommendation"><div class="recommendation-title">Recommendation</div><div>%s</div></div>`+"\n",
			html.EscapeString(finding.Recommendation))
	}
	fmt.Fprintln(w, "</div>")
}

func summaryCard(w io.Writer, label, value string) {
	fmt.Fprintf(w, `<div class="summary-card"><div class="label">%s</div><div class="value">%s</div></div>`+"\n",
		html.EscapeString(label), html.EscapeString(value))
}

func htmlHead() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApiPosture Security Scan Report</title>
    <style>
        :root { --bg:#f3f6fb; --panel:#fff; --border:#dbe3ee; --text:#1e293b; --muted:#64748b; --critical:#dc2626; --high:#ea580c; --medium:#d97706; --low:#2563eb; --shadow:rgba(15,23,42,0.08); }
        * { box-sizing:border-box; } html { scroll-behavior:smooth; }
        body { margin:0; padding:32px; background:linear-gradient(to bottom right,#f8fafc,#eef4fb); color:var(--text); font-family:Inter,Segoe UI,Arial,sans-serif; line-height:1.6; }
        .container { max-width:1500px; margin:0 auto; }
        h1 { font-size:42px; margin-bottom:8px; color:#0f172a; }
        h2 { margin-top:50px; margin-bottom:20px; border-bottom:1px solid var(--border); padding-bottom:12px; color:#0f172a; }
        h3 { margin-top:0; color:#1e293b; }
        .meta { color:var(--muted); margin-bottom:40px; }
        .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:18px; margin-bottom:40px; }
        .summary-card { background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:24px; transition:0.2s ease; box-shadow:0 6px 20px var(--shadow); }
        .summary-card:hover { transform:translateY(-2px); }
        .summary-card .label { color:var(--muted); font-size:14px; }
        .summary-card .value { font-size:34px; font-weight:700; margin-top:8px; color:#0f172a; }
        table { width:100%; border-collapse:collapse; margin-top:18px; margin-bottom:30px; border-radius:14px; box-shadow:0 6px 18px var(--shadow); }
        th { background:#eff6ff; color:#1e293b; text-align:left; padding:15px; font-size:14px; border-bottom:1px solid var(--border); }
        td { background:var(--panel); border-top:1px solid var(--border); padding:15px; vertical-align:top; }
        tr:hover td { background:#f8fbff; }
        code { background:#eef2ff; color:#1d4ed8; padding:4px 8px; border-radius:6px; font-family:Consolas,monospace; font-size:13px; }
        .finding { background:var(--panel); border:1px solid var(--border); border-left:6px solid var(--medium); border-radius:16px; padding:24px; margin-bottom:24px; transition:0.2s ease; box-shadow:0 6px 18px var(--shadow); }
        .finding:hover { transform:translateY(-2px); }
        .finding.critical { border-left-color:var(--critical); } .finding.high { border-left-color:var(--high); }
        .finding.medium { border-left-color:var(--medium); } .finding.low { border-left-color:var(--low); }
        .severity-badge { display:inline-block; padding:5px 12px; border-radius:999px; font-size:12px; font-weight:bold; text-transform:uppercase; margin-bottom:14px; }
        .severity-critical { background:#fee2e2; color:#b91c1c; } .severity-high { background:#ffedd5; color:#c2410c; }
        .severity-medium { background:#fef3c7; color:#b45309; } .severity-low { background:#dbeafe; color:#1d4ed8; }
        .severity-info { background:#e5e7eb; color:#4b5563; }
        .recommendation { margin-top:20px; background:#f8fafc; border:1px solid var(--border); border-radius:12px; padding:18px; }
        .recommendation-title { color:#2563eb; font-weight:bold; margin-bottom:10px; }
        .severity-list { padding-left:18px; } .severity-list li { margin-bottom:8px; }
        .success { padding:18px; border-radius:12px; background:#dcfce7; color:#166534; border:1px solid #86efac; font-weight:bold; }
        .section-subtitle { color:var(--muted); margin-bottom:20px; }
    </style>
</head>`
}
