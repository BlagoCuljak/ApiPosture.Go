package models

// Finding represents a security finding for an endpoint.
type Finding struct {
	// RuleID is the unique rule identifier (e.g., "AP001").
	RuleID string `json:"rule_id"`

	// RuleName is the human-readable rule name.
	RuleName string `json:"rule_name"`

	// Severity is the finding severity.
	Severity Severity `json:"severity"`

	// Message is the human-readable message.
	Message string `json:"message"`

	// Endpoint is the endpoint this finding relates to.
	Endpoint *Endpoint `json:"endpoint"`

	// Recommendation is the recommendation for fixing the issue.
	Recommendation string `json:"recommendation,omitempty"`

	// Suppressed indicates whether this finding is suppressed by configuration.
	Suppressed bool `json:"suppressed"`

	// SuppressionReason is the reason for suppression, if suppressed.
	SuppressionReason string `json:"suppression_reason,omitempty"`
}

// NewFinding creates a new Finding.
func NewFinding(ruleID, ruleName string, severity Severity, message string, endpoint *Endpoint) *Finding {
	return &Finding{
		RuleID:   ruleID,
		RuleName: ruleName,
		Severity: severity,
		Message:  message,
		Endpoint: endpoint,
	}
}

// Location returns the display string for the finding location.
func (f *Finding) Location() string {
	return f.Endpoint.Location()
}

// Route returns the endpoint route.
func (f *Finding) Route() string {
	return f.Endpoint.FullRoute()
}

// ToMap converts the finding to a map for JSON serialization.
func (f *Finding) ToMap() map[string]interface{} {
	methods := make([]string, len(f.Endpoint.Methods))
	for i, m := range f.Endpoint.Methods {
		methods[i] = string(m)
	}

	return map[string]interface{}{
		"rule_id":            f.RuleID,
		"rule_name":          f.RuleName,
		"severity":           string(f.Severity),
		"message":            f.Message,
		"recommendation":     f.Recommendation,
		"suppressed":         f.Suppressed,
		"suppression_reason": f.SuppressionReason,
		"endpoint": map[string]interface{}{
			"route":          f.Endpoint.FullRoute(),
			"methods":        methods,
			"file_path":      f.Endpoint.FilePath,
			"line_number":    f.Endpoint.LineNumber,
			"framework":      string(f.Endpoint.Framework),
			"function_name":  f.Endpoint.FunctionName,
			"class_name":     f.Endpoint.ClassName,
			"classification": string(f.Endpoint.Classification),
		},
	}
}
