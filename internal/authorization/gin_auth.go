package authorization

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// GinExtractor extracts authorization info from Gin applications.
type GinExtractor struct{}

// NewGinExtractor creates a new GinExtractor.
func NewGinExtractor() *GinExtractor {
	return &GinExtractor{}
}

// Extract extracts authorization info from middleware.
func (e *GinExtractor) Extract(middleware []string, source *astutil.ParsedSource) models.AuthorizationInfo {
	auth := models.NewAuthorizationInfo()

	for _, mw := range middleware {
		if isAllowAnonymous(mw) {
			auth.AllowsAnonymous = true
			auth.Source = "middleware"
			continue
		}

		if isAuthMiddleware(mw) {
			auth.RequiresAuth = true
			auth.AuthDependencies = append(auth.AuthDependencies, mw)
			auth.Source = "middleware"
		}

		// Check for role-based middleware
		if roles := extractRoles(mw); roles != nil {
			auth.Roles = append(auth.Roles, roles...)
		}
	}

	return auth
}
