// Package authorization provides auth extraction for various Go API frameworks.
package authorization

import (
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// Extractor is the interface for auth extraction.
type Extractor interface {
	Extract(middleware []string, source *astutil.ParsedSource) models.AuthorizationInfo
}

// Common auth middleware patterns
var authMiddlewarePatterns = []string{
	"auth",
	"jwt",
	"oauth",
	"session",
	"token",
	"bearer",
	"apikey",
	"api_key",
	"authenticate",
	"authorized",
	"requireauth",
	"require_auth",
	"protected",
	"secure",
	"guard",
	"permission",
	"role",
	"acl",
	"casbin",
}

// Common allow-anonymous patterns
var allowAnonPatterns = []string{
	"allowanonymous",
	"allow_anonymous",
	"public",
	"noauth",
	"no_auth",
	"skipauth",
	"skip_auth",
	"permitall",
	"permit_all",
}

// isAuthMiddleware checks if a middleware name indicates authentication.
func isAuthMiddleware(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range authMiddlewarePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// isAllowAnonymous checks if a middleware name indicates anonymous access.
func isAllowAnonymous(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range allowAnonPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// extractRoles extracts role names from middleware that looks like role middleware.
func extractRoles(name string) []string {
	lower := strings.ToLower(name)

	// Check for common role middleware patterns
	// e.g., RequireRole("admin"), HasRole("admin")
	if strings.Contains(lower, "role") || strings.Contains(lower, "permission") {
		// We can't extract the actual role values from static analysis
		// Just mark that roles are required
		return []string{}
	}

	return nil
}
