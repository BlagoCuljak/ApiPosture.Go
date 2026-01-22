package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPMethod_IsWriteMethod(t *testing.T) {
	tests := []struct {
		method   HTTPMethod
		expected bool
	}{
		{MethodGET, false},
		{MethodPOST, true},
		{MethodPUT, true},
		{MethodDELETE, true},
		{MethodPATCH, true},
		{MethodHEAD, false},
		{MethodOPTIONS, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.method.IsWriteMethod())
		})
	}
}

func TestSeverity_Order(t *testing.T) {
	assert.Less(t, SeverityInfo.Order(), SeverityLow.Order())
	assert.Less(t, SeverityLow.Order(), SeverityMedium.Order())
	assert.Less(t, SeverityMedium.Order(), SeverityHigh.Order())
	assert.Less(t, SeverityHigh.Order(), SeverityCritical.Order())
}

func TestSeverity_GreaterOrEqual(t *testing.T) {
	assert.True(t, SeverityCritical.GreaterOrEqual(SeverityInfo))
	assert.True(t, SeverityHigh.GreaterOrEqual(SeverityMedium))
	assert.True(t, SeverityMedium.GreaterOrEqual(SeverityMedium))
	assert.False(t, SeverityLow.GreaterOrEqual(SeverityHigh))
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"info", SeverityInfo},
		{"low", SeverityLow},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"critical", SeverityCritical},
		{"unknown", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseSeverity(tt.input))
		})
	}
}
