package rules

import (
	"fmt"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// AP008EndpointWithoutAuth flags endpoints without any auth configuration.
type AP008EndpointWithoutAuth struct{}

// NewAP008EndpointWithoutAuth creates a new AP008 rule.
func NewAP008EndpointWithoutAuth() *AP008EndpointWithoutAuth {
	return &AP008EndpointWithoutAuth{}
}

// ID returns the rule ID.
func (r *AP008EndpointWithoutAuth) ID() string {
	return "AP008"
}

// Name returns the rule name.
func (r *AP008EndpointWithoutAuth) Name() string {
	return "Endpoint without authentication"
}

// Severity returns the rule severity.
func (r *AP008EndpointWithoutAuth) Severity() models.Severity {
	return models.SeverityHigh
}

// Description returns the rule description.
func (r *AP008EndpointWithoutAuth) Description() string {
	return "Endpoint has no authentication configuration. " +
		"Consider adding authentication middleware."
}

// Evaluate checks if endpoint lacks authentication.
func (r *AP008EndpointWithoutAuth) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	// Only check public endpoints
	if endpoint.Classification != models.ClassificationPublic {
		return nil
	}

	// Skip if explicitly allowing anonymous
	if endpoint.Authorization.AllowsAnonymous {
		return nil
	}

	auth := &endpoint.Authorization

	// Check if there's any auth configuration
	if auth.RequiresAuth || len(auth.AuthDependencies) > 0 || auth.HasSpecificRequirements() {
		return nil
	}

	// Build framework-specific recommendation
	var recommendation string
	switch endpoint.Framework {
	case models.FrameworkGin:
		recommendation = "Add authentication middleware: use gin-jwt, gin-session, or custom auth middleware"
	case models.FrameworkEcho:
		recommendation = "Add authentication middleware: use echo-jwt, echo middleware, or custom auth handler"
	case models.FrameworkChi:
		recommendation = "Add authentication middleware: use chi middleware with jwtauth or custom auth handler"
	case models.FrameworkFiber:
		recommendation = "Add authentication middleware: use fiber-jwt, fiber-session, or custom auth middleware"
	case models.FrameworkNetHTTP:
		recommendation = "Add authentication: wrap handler with auth middleware or check auth in handler"
	default:
		recommendation = "Add authentication middleware to protect this endpoint"
	}

	return []*models.Finding{
		createFinding(r, endpoint,
			fmt.Sprintf("Endpoint '%s' has no authentication configuration", endpoint.FullRoute()),
			recommendation,
		),
	}
}
