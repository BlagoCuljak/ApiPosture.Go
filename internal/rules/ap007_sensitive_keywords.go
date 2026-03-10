package rules

import (
	"fmt"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// sensitiveKeywords are keywords that indicate potentially sensitive routes.
// Only use segment-level exact-match terms; avoid substrings of common public words.
var sensitiveKeywords = []string{
	"admin",
	"debug",
	"export",
	"import",
	"internal",
	"config",
	"settings",
	"secret",
	"private",
	"management",
	"manage",
	"system",
	"backup",
	"restore",
	"migrate",
	"database",
	"db",
	"console",
	"shell",
	"exec",
	"execute",
	"eval",
	"trace",
	"metrics",
	"actuator",
}

// AP007SensitiveKeywords flags public routes with sensitive keywords.
type AP007SensitiveKeywords struct{}

// NewAP007SensitiveKeywords creates a new AP007 rule.
func NewAP007SensitiveKeywords() *AP007SensitiveKeywords {
	return &AP007SensitiveKeywords{}
}

// ID returns the rule ID.
func (r *AP007SensitiveKeywords) ID() string {
	return "AP007"
}

// Name returns the rule name.
func (r *AP007SensitiveKeywords) Name() string {
	return "Sensitive keyword in public route"
}

// Severity returns the rule severity.
func (r *AP007SensitiveKeywords) Severity() models.Severity {
	return models.SeverityMedium
}

// Description returns the rule description.
func (r *AP007SensitiveKeywords) Description() string {
	return "Public route contains sensitive keywords suggesting it should be protected. " +
		"Routes with admin, debug, export, or internal keywords often require authentication."
}

// Evaluate checks for sensitive keywords in public routes.
func (r *AP007SensitiveKeywords) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	// Only check public endpoints
	if endpoint.Classification != models.ClassificationPublic {
		return nil
	}

	// Skip if explicitly anonymous (intentional)
	if endpoint.Authorization.AllowsAnonymous {
		return nil
	}

	route := strings.ToLower(endpoint.FullRoute())
	// Split route into segments for exact-match comparison; this prevents
	// substrings like "log" matching "/catalog" or "info" matching "/information".
	rawSegments := strings.FieldsFunc(route, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
	segSet := make(map[string]bool, len(rawSegments))
	for _, s := range rawSegments {
		segSet[s] = true
	}

	var found []string
	for _, keyword := range sensitiveKeywords {
		if segSet[keyword] {
			found = append(found, keyword)
		}
	}

	if len(found) == 0 {
		return nil
	}

	return []*models.Finding{
		createFinding(r, endpoint,
			fmt.Sprintf("Public route '%s' contains sensitive keywords: %s",
				endpoint.FullRoute(), strings.Join(found, ", ")),
			"Consider adding authentication to this endpoint or marking it as intentionally public",
		),
	}
}
