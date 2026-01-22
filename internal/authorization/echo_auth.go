package authorization

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// EchoExtractor extracts authorization info from Echo applications.
type EchoExtractor struct{}

// NewEchoExtractor creates a new EchoExtractor.
func NewEchoExtractor() *EchoExtractor {
	return &EchoExtractor{}
}

// Extract extracts authorization info from middleware.
func (e *EchoExtractor) Extract(middleware []string, source *astutil.ParsedSource) models.AuthorizationInfo {
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
