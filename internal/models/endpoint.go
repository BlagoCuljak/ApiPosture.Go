package models

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Endpoint represents a discovered API endpoint.
type Endpoint struct {
	// Route is the path (e.g., "/api/users/:id").
	Route string `json:"route"`

	// Methods contains the HTTP method(s) this endpoint handles.
	Methods []HTTPMethod `json:"methods"`

	// FilePath is the source file path.
	FilePath string `json:"file_path"`

	// LineNumber is the line number where the endpoint is defined.
	LineNumber int `json:"line_number"`

	// Framework is the framework that defines this endpoint.
	Framework Framework `json:"framework"`

	// EndpointType is the type of endpoint definition.
	EndpointType EndpointType `json:"endpoint_type"`

	// FunctionName is the name of the function/method.
	FunctionName string `json:"function_name"`

	// ClassName is the name of the class (for class-based views), if any.
	ClassName string `json:"class_name,omitempty"`

	// Authorization contains authorization information.
	Authorization AuthorizationInfo `json:"authorization"`

	// Classification is the security classification (computed).
	Classification SecurityClassification `json:"classification"`

	// RouterPrefix is the router/group prefix, if any.
	RouterPrefix string `json:"router_prefix,omitempty"`

	// Tags are for grouping (similar to Gin groups, etc.).
	Tags []string `json:"tags,omitempty"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewEndpoint creates a new Endpoint with default values.
func NewEndpoint() *Endpoint {
	return &Endpoint{
		Methods:        []HTTPMethod{},
		Authorization:  NewAuthorizationInfo(),
		Classification: ClassificationPublic,
		Tags:           []string{},
		Metadata:       make(map[string]string),
	}
}

// FullRoute returns the full route including router prefix.
func (e *Endpoint) FullRoute() string {
	if e.RouterPrefix == "" {
		return e.Route
	}

	prefix := strings.TrimSuffix(e.RouterPrefix, "/")
	route := e.Route
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	return prefix + route
}

// DisplayMethods returns a display string for the HTTP methods.
func (e *Endpoint) DisplayMethods() string {
	if len(e.Methods) == 0 {
		return ""
	}

	methods := make([]string, len(e.Methods))
	for i, m := range e.Methods {
		methods[i] = string(m)
	}
	return strings.Join(methods, ", ")
}

// Location returns a display string for the file location.
func (e *Endpoint) Location() string {
	return fmt.Sprintf("%s:%d", e.FilePath, e.LineNumber)
}

// ShortLocation returns a display string with just filename and line.
func (e *Endpoint) ShortLocation() string {
	return fmt.Sprintf("%s:%d", filepath.Base(e.FilePath), e.LineNumber)
}

// IsWriteEndpoint returns true if this endpoint handles any write methods.
func (e *Endpoint) IsWriteEndpoint() bool {
	for _, m := range e.Methods {
		if m.IsWriteMethod() {
			return true
		}
	}
	return false
}

// Hash returns a string hash based on route, methods, and file location.
func (e *Endpoint) Hash() string {
	methods := make([]string, len(e.Methods))
	for i, m := range e.Methods {
		methods[i] = string(m)
	}
	sort.Strings(methods)
	return fmt.Sprintf("%s|%s|%s|%d", e.Route, strings.Join(methods, ","), e.FilePath, e.LineNumber)
}

// Equal returns true if two endpoints are equal based on route, methods, and file location.
func (e *Endpoint) Equal(other *Endpoint) bool {
	if e.Route != other.Route || e.FilePath != other.FilePath || e.LineNumber != other.LineNumber {
		return false
	}

	if len(e.Methods) != len(other.Methods) {
		return false
	}

	// Create sets for comparison
	methodSet := make(map[HTTPMethod]bool)
	for _, m := range e.Methods {
		methodSet[m] = true
	}

	for _, m := range other.Methods {
		if !methodSet[m] {
			return false
		}
	}

	return true
}
