package rules

import "strings"

// knownPublicSegments are route path segments that are conventionally public.
// They cover auth entry points and infrastructure probes (health checks, OAuth callbacks, etc.)
var knownPublicSegments = map[string]bool{
	// auth entry points
	"login": true, "logout": true, "signin": true, "signout": true,
	"signup": true, "register": true, "registration": true,
	"forgot": true, "reset": true, "verify": true, "confirm": true,
	"activate": true, "deactivate": true, "unsubscribe": true, "resend": true,
	"callback": true, "authorize": true, "oauth": true, "openid": true,
	"token": true, "refresh": true, "exchange": true, "revoke": true,
	"2fa": true, "totp": true, "mfa": true, "otp": true,
	"auth": true,
	// infrastructure probes
	"health": true, "healthz": true, "liveness": true, "readiness": true,
	"ping": true, "ready": true, "alive": true, "startup": true,
	// public docs
	"swagger": true, "openapi": true, "docs": true, "redoc": true,
	// public webhooks and SSO
	"webhook": true, "webhooks": true, "sso": true, "saml": true, "wsfed": true,
	// public grant endpoints
	"grant": true,
}

// isKnownPublicEndpoint returns true if the route is a well-known public endpoint
// that should never require authentication (auth entry points, health checks, etc.)
func isKnownPublicEndpoint(route string) bool {
	if route == "" || route == "/" {
		return false
	}
	lower := strings.ToLower(route)
	// Split on path separators and common delimiters
	segments := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
	for _, seg := range segments {
		// Skip parameter segments like :id, {id}, *
		if seg == "" || seg == "*" || strings.HasPrefix(seg, ":") ||
			(strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")) {
			continue
		}
		if knownPublicSegments[seg] {
			return true
		}
	}
	return false
}
