package rules

import (
	"fmt"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// AP004MissingAuthWrites flags write endpoints without any authentication.
type AP004MissingAuthWrites struct{}

// NewAP004MissingAuthWrites creates a new AP004 rule.
func NewAP004MissingAuthWrites() *AP004MissingAuthWrites {
	return &AP004MissingAuthWrites{}
}

// ID returns the rule ID.
func (r *AP004MissingAuthWrites) ID() string {
	return "AP004"
}

// Name returns the rule name.
func (r *AP004MissingAuthWrites) Name() string {
	return "Missing authentication on write endpoint"
}

// Severity returns the rule severity.
func (r *AP004MissingAuthWrites) Severity() models.Severity {
	return models.SeverityCritical
}

// Description returns the rule description.
func (r *AP004MissingAuthWrites) Description() string {
	return "Write endpoints (POST, PUT, DELETE, PATCH) without any authentication. " +
		"This is a critical security risk allowing unauthorized data modification."
}

// Evaluate checks if write endpoint is missing authentication.
func (r *AP004MissingAuthWrites) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	// Only check write endpoints
	if !endpoint.IsWriteEndpoint() {
		return nil
	}

	// Only flag if classified as public
	if endpoint.Classification != models.ClassificationPublic {
		return nil
	}

	auth := &endpoint.Authorization

	// Skip if explicitly allowing anonymous (covered by AP002)
	if auth.AllowsAnonymous {
		return nil
	}

	// Flag if there's no auth at all
	if !auth.RequiresAuth && len(auth.AuthDependencies) == 0 && !auth.HasSpecificRequirements() {
		return []*models.Finding{
			createFinding(r, endpoint,
				fmt.Sprintf("Write endpoint '%s' [%s] has no authentication",
					endpoint.FullRoute(), endpoint.DisplayMethods()),
				"Add authentication middleware to protect this write endpoint",
			),
		}
	}

	return nil
}
