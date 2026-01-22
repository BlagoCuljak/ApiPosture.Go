package models

import "time"

// ScanResult contains all analysis results.
type ScanResult struct {
	// ScanPath is the path that was scanned.
	ScanPath string `json:"scan_path"`

	// Endpoints contains all discovered endpoints.
	Endpoints []*Endpoint `json:"endpoints"`

	// Findings contains all security findings.
	Findings []*Finding `json:"findings"`

	// FilesScanned contains files that were scanned.
	FilesScanned []string `json:"files_scanned"`

	// ParseErrors maps files to their parse errors.
	ParseErrors map[string]string `json:"parse_errors"`

	// FrameworksDetected contains detected frameworks.
	FrameworksDetected map[Framework]bool `json:"-"`

	// StartTime is the scan start time.
	StartTime time.Time `json:"start_time"`

	// EndTime is the scan end time.
	EndTime time.Time `json:"end_time"`
}

// NewScanResult creates a new ScanResult.
func NewScanResult(scanPath string) *ScanResult {
	return &ScanResult{
		ScanPath:           scanPath,
		Endpoints:          []*Endpoint{},
		Findings:           []*Finding{},
		FilesScanned:       []string{},
		ParseErrors:        make(map[string]string),
		FrameworksDetected: make(map[Framework]bool),
		StartTime:          time.Now(),
	}
}

// DurationMs returns the scan duration in milliseconds.
func (r *ScanResult) DurationMs() int64 {
	if r.EndTime.IsZero() {
		return 0
	}
	return r.EndTime.Sub(r.StartTime).Milliseconds()
}

// ActiveFindings returns findings that are not suppressed.
func (r *ScanResult) ActiveFindings() []*Finding {
	var active []*Finding
	for _, f := range r.Findings {
		if !f.Suppressed {
			active = append(active, f)
		}
	}
	return active
}

// SuppressedFindings returns findings that are suppressed.
func (r *ScanResult) SuppressedFindings() []*Finding {
	var suppressed []*Finding
	for _, f := range r.Findings {
		if f.Suppressed {
			suppressed = append(suppressed, f)
		}
	}
	return suppressed
}

// FindingsBySeverity returns active findings of a specific severity.
func (r *ScanResult) FindingsBySeverity(severity Severity) []*Finding {
	var findings []*Finding
	for _, f := range r.ActiveFindings() {
		if f.Severity == severity {
			findings = append(findings, f)
		}
	}
	return findings
}

// FindingsAtOrAbove returns active findings at or above a severity level.
func (r *ScanResult) FindingsAtOrAbove(severity Severity) []*Finding {
	var findings []*Finding
	for _, f := range r.ActiveFindings() {
		if f.Severity.GreaterOrEqual(severity) {
			findings = append(findings, f)
		}
	}
	return findings
}

// HasCritical returns true if there are any critical findings.
func (r *ScanResult) HasCritical() bool {
	for _, f := range r.ActiveFindings() {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHigh returns true if there are any high or critical findings.
func (r *ScanResult) HasHigh() bool {
	for _, f := range r.ActiveFindings() {
		if f.Severity.GreaterOrEqual(SeverityHigh) {
			return true
		}
	}
	return false
}

// SeveritySummary returns a summary of findings by severity.
func (r *ScanResult) SeveritySummary() map[Severity]int {
	summary := map[Severity]int{
		SeverityInfo:     0,
		SeverityLow:      0,
		SeverityMedium:   0,
		SeverityHigh:     0,
		SeverityCritical: 0,
	}

	for _, f := range r.ActiveFindings() {
		summary[f.Severity]++
	}

	return summary
}

// FrameworksList returns a list of detected frameworks.
func (r *ScanResult) FrameworksList() []Framework {
	var frameworks []Framework
	for f := range r.FrameworksDetected {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// ToMap converts the result to a map for JSON serialization.
func (r *ScanResult) ToMap() map[string]interface{} {
	frameworks := make([]string, 0, len(r.FrameworksDetected))
	for f := range r.FrameworksDetected {
		frameworks = append(frameworks, string(f))
	}

	endpoints := make([]map[string]interface{}, len(r.Endpoints))
	for i, e := range r.Endpoints {
		methods := make([]string, len(e.Methods))
		for j, m := range e.Methods {
			methods[j] = string(m)
		}

		endpoints[i] = map[string]interface{}{
			"route":          e.FullRoute(),
			"methods":        methods,
			"file_path":      e.FilePath,
			"line_number":    e.LineNumber,
			"framework":      string(e.Framework),
			"classification": string(e.Classification),
			"function_name":  e.FunctionName,
			"class_name":     e.ClassName,
		}
	}

	findings := make([]map[string]interface{}, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = f.ToMap()
	}

	severityCounts := make(map[string]int)
	for sev, count := range r.SeveritySummary() {
		severityCounts[string(sev)] = count
	}

	return map[string]interface{}{
		"scan_path":           r.ScanPath,
		"files_scanned":       len(r.FilesScanned),
		"parse_errors":        len(r.ParseErrors),
		"frameworks_detected": frameworks,
		"duration_ms":         r.DurationMs(),
		"summary": map[string]interface{}{
			"total_endpoints":     len(r.Endpoints),
			"total_findings":      len(r.ActiveFindings()),
			"suppressed_findings": len(r.SuppressedFindings()),
			"severity_counts":     severityCounts,
		},
		"endpoints": endpoints,
		"findings":  findings,
	}
}
