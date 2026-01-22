// Package classification provides security classification logic for endpoints.
package classification

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// Classifier classifies endpoints based on their authorization configuration.
type Classifier struct{}

// NewClassifier creates a new Classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// Classify determines the security classification of an endpoint.
//
// Classifications:
// - PUBLIC: No authorization required (AllowAnonymous or no auth)
// - AUTHENTICATED: Requires authentication but no specific roles/permissions
// - ROLE_RESTRICTED: Requires specific roles
// - POLICY_RESTRICTED: Requires specific policies/permissions/scopes
func (c *Classifier) Classify(endpoint *models.Endpoint) models.SecurityClassification {
	auth := &endpoint.Authorization

	// Check if explicitly public
	if auth.AllowsAnonymous {
		return models.ClassificationPublic
	}

	// Check if no auth required
	if !auth.RequiresAuth && !auth.HasSpecificRequirements() {
		return models.ClassificationPublic
	}

	// Check for policy/permission restrictions
	if len(auth.Policies) > 0 || len(auth.Permissions) > 0 || len(auth.Scopes) > 0 {
		return models.ClassificationPolicyRestricted
	}

	// Check for role restrictions
	if len(auth.Roles) > 0 {
		return models.ClassificationRoleRestricted
	}

	// Has auth but no specific requirements
	if auth.RequiresAuth || len(auth.AuthDependencies) > 0 {
		return models.ClassificationAuthenticated
	}

	return models.ClassificationPublic
}

// ClassifyAll classifies all endpoints in place.
func (c *Classifier) ClassifyAll(endpoints []*models.Endpoint) {
	for _, endpoint := range endpoints {
		endpoint.Classification = c.Classify(endpoint)
	}
}
