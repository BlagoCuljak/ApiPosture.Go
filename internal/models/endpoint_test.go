package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndpoint_FullRoute(t *testing.T) {
	tests := []struct {
		name         string
		route        string
		routerPrefix string
		expected     string
	}{
		{
			name:         "no prefix",
			route:        "/users",
			routerPrefix: "",
			expected:     "/users",
		},
		{
			name:         "with prefix",
			route:        "/users",
			routerPrefix: "/api/v1",
			expected:     "/api/v1/users",
		},
		{
			name:         "prefix with trailing slash",
			route:        "/users",
			routerPrefix: "/api/v1/",
			expected:     "/api/v1/users",
		},
		{
			name:         "route without leading slash",
			route:        "users",
			routerPrefix: "/api",
			expected:     "/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				Route:        tt.route,
				RouterPrefix: tt.routerPrefix,
			}
			assert.Equal(t, tt.expected, e.FullRoute())
		})
	}
}

func TestEndpoint_DisplayMethods(t *testing.T) {
	tests := []struct {
		name     string
		methods  []HTTPMethod
		expected string
	}{
		{
			name:     "single method",
			methods:  []HTTPMethod{MethodGET},
			expected: "GET",
		},
		{
			name:     "multiple methods",
			methods:  []HTTPMethod{MethodGET, MethodPOST},
			expected: "GET, POST",
		},
		{
			name:     "no methods",
			methods:  []HTTPMethod{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{Methods: tt.methods}
			assert.Equal(t, tt.expected, e.DisplayMethods())
		})
	}
}

func TestEndpoint_IsWriteEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		methods  []HTTPMethod
		expected bool
	}{
		{
			name:     "GET only",
			methods:  []HTTPMethod{MethodGET},
			expected: false,
		},
		{
			name:     "POST",
			methods:  []HTTPMethod{MethodPOST},
			expected: true,
		},
		{
			name:     "GET and POST",
			methods:  []HTTPMethod{MethodGET, MethodPOST},
			expected: true,
		},
		{
			name:     "HEAD and OPTIONS",
			methods:  []HTTPMethod{MethodHEAD, MethodOPTIONS},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{Methods: tt.methods}
			assert.Equal(t, tt.expected, e.IsWriteEndpoint())
		})
	}
}

func TestEndpoint_Location(t *testing.T) {
	e := &Endpoint{
		FilePath:   "/path/to/file.go",
		LineNumber: 42,
	}
	assert.Equal(t, "/path/to/file.go:42", e.Location())
}

func TestEndpoint_ShortLocation(t *testing.T) {
	e := &Endpoint{
		FilePath:   "/path/to/file.go",
		LineNumber: 42,
	}
	assert.Equal(t, "file.go:42", e.ShortLocation())
}
