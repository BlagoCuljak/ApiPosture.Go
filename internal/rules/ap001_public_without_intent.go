package rules

import (
	"fmt"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// AP001PublicWithoutIntent flags public endpoints without explicit intent.
type AP001PublicWithoutIntent struct{}

// NewAP001PublicWithoutIntent creates a new AP001 rule.
func NewAP001PublicWithoutIntent() *AP001PublicWithoutIntent {
	return &AP001PublicWithoutIntent{}
}

// ID returns the rule ID.
func (r *AP001PublicWithoutIntent) ID() string {
	return "AP001"
}

// Name returns the rule name.
func (r *AP001PublicWithoutIntent) Name() string {
	return "Public without explicit intent"
}

// Severity returns the rule severity.
func (r *AP001PublicWithoutIntent) Severity() models.Severity {
	return models.SeverityHigh
}

// Description returns the rule description.
func (r *AP001PublicWithoutIntent) Description() string {
	return "Public endpoint without explicit authorization intent. " +
		"Endpoints should explicitly declare their authorization requirements."
}

// Evaluate checks if endpoint is public without explicit AllowAnonymous.
func (r *AP001PublicWithoutIntent) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	if endpoint.Classification != models.ClassificationPublic {
		return nil
	}

	auth := &endpoint.Authorization

	// If explicitly marked as anonymous/public, this is intentional
	if auth.AllowsAnonymous {
		return nil
	}

	// If there's any auth configuration at all, skip
	if auth.RequiresAuth || len(auth.AuthDependencies) > 0 || auth.HasSpecificRequirements() {
		return nil
	}

	return []*models.Finding{
		createFinding(r, endpoint,
			fmt.Sprintf("Endpoint '%s' is public without explicit authorization intent", endpoint.FullRoute()),
			"Add explicit authorization middleware or mark as intentionally public",
		),
	}
}
