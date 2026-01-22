package rules

import (
	"fmt"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// AP003AuthConflict flags authorization conflicts between group and route.
type AP003AuthConflict struct{}

// NewAP003AuthConflict creates a new AP003 rule.
func NewAP003AuthConflict() *AP003AuthConflict {
	return &AP003AuthConflict{}
}

// ID returns the rule ID.
func (r *AP003AuthConflict) ID() string {
	return "AP003"
}

// Name returns the rule name.
func (r *AP003AuthConflict) Name() string {
	return "Group/route authorization conflict"
}

// Severity returns the rule severity.
func (r *AP003AuthConflict) Severity() models.Severity {
	return models.SeverityMedium
}

// Description returns the rule description.
func (r *AP003AuthConflict) Description() string {
	return "Route-level anonymous access overrides group-level authentication. " +
		"This may indicate a configuration mistake."
}

// Evaluate checks for group/route authorization conflicts.
func (r *AP003AuthConflict) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	auth := &endpoint.Authorization

	// Check if route allows anonymous but inherited auth requires it
	if auth.AllowsAnonymous && auth.Inherited {
		return []*models.Finding{
			createFinding(r, endpoint,
				fmt.Sprintf("Route '%s' allows anonymous access, overriding group-level authentication",
					endpoint.FullRoute()),
				"Verify this override is intentional. If the route should be public, consider documenting why with a comment",
			),
		}
	}

	return nil
}
