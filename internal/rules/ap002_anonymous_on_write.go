package rules

import (
	"fmt"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// AP002AnonymousOnWrite flags write endpoints with explicit anonymous access.
type AP002AnonymousOnWrite struct{}

// NewAP002AnonymousOnWrite creates a new AP002 rule.
func NewAP002AnonymousOnWrite() *AP002AnonymousOnWrite {
	return &AP002AnonymousOnWrite{}
}

// ID returns the rule ID.
func (r *AP002AnonymousOnWrite) ID() string {
	return "AP002"
}

// Name returns the rule name.
func (r *AP002AnonymousOnWrite) Name() string {
	return "Anonymous access on write endpoint"
}

// Severity returns the rule severity.
func (r *AP002AnonymousOnWrite) Severity() models.Severity {
	return models.SeverityHigh
}

// Description returns the rule description.
func (r *AP002AnonymousOnWrite) Description() string {
	return "Write endpoints (POST, PUT, DELETE, PATCH) with explicit anonymous access. " +
		"This can allow unauthorized data modification."
}

// Evaluate checks if write endpoint allows anonymous access.
func (r *AP002AnonymousOnWrite) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	// Only check write endpoints
	if !endpoint.IsWriteEndpoint() {
		return nil
	}

	// Only flag if explicitly allowing anonymous
	if !endpoint.Authorization.AllowsAnonymous {
		return nil
	}

	return []*models.Finding{
		createFinding(r, endpoint,
			fmt.Sprintf("Write endpoint '%s' [%s] explicitly allows anonymous access",
				endpoint.FullRoute(), endpoint.DisplayMethods()),
			"Remove anonymous access from write endpoints, or add rate limiting and validation if public access is required",
		),
	}
}
