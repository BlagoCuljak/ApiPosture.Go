package authorization

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// NetHTTPExtractor extracts authorization info from net/http applications.
type NetHTTPExtractor struct{}

// NewNetHTTPExtractor creates a new NetHTTPExtractor.
func NewNetHTTPExtractor() *NetHTTPExtractor {
	return &NetHTTPExtractor{}
}

// Extract extracts authorization info from middleware.
func (e *NetHTTPExtractor) Extract(middleware []string, source *astutil.ParsedSource) models.AuthorizationInfo {
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
