// Package models contains core data structures for ApiPosture.
package models

// HTTPMethod represents an HTTP method.
type HTTPMethod string

const (
	MethodGET     HTTPMethod = "GET"
	MethodPOST    HTTPMethod = "POST"
	MethodPUT     HTTPMethod = "PUT"
	MethodDELETE  HTTPMethod = "DELETE"
	MethodPATCH   HTTPMethod = "PATCH"
	MethodHEAD    HTTPMethod = "HEAD"
	MethodOPTIONS HTTPMethod = "OPTIONS"
)

// IsWriteMethod returns true if the method modifies state.
func (m HTTPMethod) IsWriteMethod() bool {
	switch m {
	case MethodPOST, MethodPUT, MethodDELETE, MethodPATCH:
		return true
	default:
		return false
	}
}

// String returns the string representation of the HTTP method.
func (m HTTPMethod) String() string {
	return string(m)
}

// Framework represents a supported Go API framework.
type Framework string

const (
	FrameworkGin     Framework = "gin"
	FrameworkEcho    Framework = "echo"
	FrameworkChi     Framework = "chi"
	FrameworkFiber   Framework = "fiber"
	FrameworkNetHTTP Framework = "net/http"
	FrameworkUnknown Framework = "unknown"
)

// String returns the string representation of the framework.
func (f Framework) String() string {
	return string(f)
}

// SecurityClassification represents the security classification of an endpoint.
type SecurityClassification string

const (
	ClassificationPublic           SecurityClassification = "public"
	ClassificationAuthenticated    SecurityClassification = "authenticated"
	ClassificationRoleRestricted   SecurityClassification = "role_restricted"
	ClassificationPolicyRestricted SecurityClassification = "policy_restricted"
)

// String returns the string representation of the classification.
func (c SecurityClassification) String() string {
	return string(c)
}

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Order returns the numeric order for sorting (higher = more severe).
func (s Severity) Order() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// GreaterOrEqual returns true if this severity is >= other.
func (s Severity) GreaterOrEqual(other Severity) bool {
	return s.Order() >= other.Order()
}

// ParseSeverity parses a string to Severity.
func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// EndpointType represents the type of endpoint definition.
type EndpointType string

const (
	EndpointTypeControllerAction EndpointType = "controller_action"
	EndpointTypeFunction         EndpointType = "function"
	EndpointTypeRouter           EndpointType = "router"
)

// String returns the string representation of the endpoint type.
func (e EndpointType) String() string {
	return string(e)
}
