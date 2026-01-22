// Package rules provides security rules for API endpoint analysis.
package rules

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// Rule is the interface for security rules.
type Rule interface {
	// ID returns the unique rule identifier (e.g., "AP001").
	ID() string

	// Name returns the human-readable rule name.
	Name() string

	// Severity returns the default severity level.
	Severity() models.Severity

	// Description returns the rule description.
	Description() string

	// Evaluate evaluates the rule against an endpoint.
	Evaluate(endpoint *models.Endpoint) []*models.Finding
}

// createFinding is a helper to create a finding with standard fields.
func createFinding(rule Rule, endpoint *models.Endpoint, message, recommendation string) *models.Finding {
	return &models.Finding{
		RuleID:         rule.ID(),
		RuleName:       rule.Name(),
		Severity:       rule.Severity(),
		Message:        message,
		Endpoint:       endpoint,
		Recommendation: recommendation,
	}
}
