package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

func TestAP001_PublicWithoutIntent(t *testing.T) {
	rule := NewAP001PublicWithoutIntent()

	tests := []struct {
		name           string
		endpoint       *models.Endpoint
		expectFinding  bool
	}{
		{
			name: "public endpoint without explicit intent",
			endpoint: &models.Endpoint{
				Route:          "/users",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: true,
		},
		{
			name: "public endpoint with explicit AllowAnonymous",
			endpoint: &models.Endpoint{
				Route:          "/health",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization: models.AuthorizationInfo{
					AllowsAnonymous: true,
				},
			},
			expectFinding: false,
		},
		{
			name: "authenticated endpoint",
			endpoint: &models.Endpoint{
				Route:          "/api/users",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationAuthenticated,
				Authorization: models.AuthorizationInfo{
					RequiresAuth: true,
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Evaluate(tt.endpoint)
			if tt.expectFinding {
				assert.Len(t, findings, 1)
				assert.Equal(t, "AP001", findings[0].RuleID)
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

func TestAP002_AnonymousOnWrite(t *testing.T) {
	rule := NewAP002AnonymousOnWrite()

	tests := []struct {
		name          string
		endpoint      *models.Endpoint
		expectFinding bool
	}{
		{
			name: "write endpoint with anonymous access",
			endpoint: &models.Endpoint{
				Route:          "/api/submit",
				Methods:        []models.HTTPMethod{models.MethodPOST},
				Classification: models.ClassificationPublic,
				Authorization: models.AuthorizationInfo{
					AllowsAnonymous: true,
				},
			},
			expectFinding: true,
		},
		{
			name: "GET endpoint with anonymous access",
			endpoint: &models.Endpoint{
				Route:          "/api/data",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization: models.AuthorizationInfo{
					AllowsAnonymous: true,
				},
			},
			expectFinding: false,
		},
		{
			name: "write endpoint without anonymous flag",
			endpoint: &models.Endpoint{
				Route:          "/api/submit",
				Methods:        []models.HTTPMethod{models.MethodPOST},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Evaluate(tt.endpoint)
			if tt.expectFinding {
				assert.Len(t, findings, 1)
				assert.Equal(t, "AP002", findings[0].RuleID)
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

func TestAP004_MissingAuthWrites(t *testing.T) {
	rule := NewAP004MissingAuthWrites()

	tests := []struct {
		name          string
		endpoint      *models.Endpoint
		expectFinding bool
	}{
		{
			name: "public POST without auth",
			endpoint: &models.Endpoint{
				Route:          "/api/users",
				Methods:        []models.HTTPMethod{models.MethodPOST},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: true,
		},
		{
			name: "public DELETE without auth",
			endpoint: &models.Endpoint{
				Route:          "/api/users/1",
				Methods:        []models.HTTPMethod{models.MethodDELETE},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: true,
		},
		{
			name: "authenticated POST",
			endpoint: &models.Endpoint{
				Route:          "/api/users",
				Methods:        []models.HTTPMethod{models.MethodPOST},
				Classification: models.ClassificationAuthenticated,
				Authorization: models.AuthorizationInfo{
					RequiresAuth: true,
				},
			},
			expectFinding: false,
		},
		{
			name: "public GET",
			endpoint: &models.Endpoint{
				Route:          "/api/users",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Evaluate(tt.endpoint)
			if tt.expectFinding {
				assert.Len(t, findings, 1)
				assert.Equal(t, "AP004", findings[0].RuleID)
				assert.Equal(t, models.SeverityCritical, findings[0].Severity)
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

func TestAP007_SensitiveKeywords(t *testing.T) {
	rule := NewAP007SensitiveKeywords()

	tests := []struct {
		name          string
		endpoint      *models.Endpoint
		expectFinding bool
	}{
		{
			name: "public admin route",
			endpoint: &models.Endpoint{
				Route:          "/admin/dashboard",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: true,
		},
		{
			name: "public debug route",
			endpoint: &models.Endpoint{
				Route:          "/debug/vars",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: true,
		},
		{
			name: "authenticated admin route",
			endpoint: &models.Endpoint{
				Route:          "/admin/dashboard",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationAuthenticated,
				Authorization: models.AuthorizationInfo{
					RequiresAuth: true,
				},
			},
			expectFinding: false,
		},
		{
			name: "public normal route",
			endpoint: &models.Endpoint{
				Route:          "/api/users",
				Methods:        []models.HTTPMethod{models.MethodGET},
				Classification: models.ClassificationPublic,
				Authorization:  models.NewAuthorizationInfo(),
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Evaluate(tt.endpoint)
			if tt.expectFinding {
				assert.Len(t, findings, 1)
				assert.Equal(t, "AP007", findings[0].RuleID)
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

func TestEngine_EvaluateAll(t *testing.T) {
	engine := NewEngine(nil)

	endpoints := []*models.Endpoint{
		{
			Route:          "/admin/users",
			Methods:        []models.HTTPMethod{models.MethodDELETE},
			Classification: models.ClassificationPublic,
			Authorization:  models.NewAuthorizationInfo(),
			Framework:      models.FrameworkGin,
		},
	}

	findings := engine.EvaluateAll(endpoints)

	// Should trigger multiple rules: AP001, AP004, AP007, AP008
	require.NotEmpty(t, findings)

	// Check that we have findings from different rules
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}

	assert.True(t, ruleIDs["AP001"], "Expected AP001 finding")
	assert.True(t, ruleIDs["AP004"], "Expected AP004 finding")
	assert.True(t, ruleIDs["AP007"], "Expected AP007 finding")
}

func TestEngine_WithEnabledRules(t *testing.T) {
	engine := NewEngine([]string{"AP001", "AP002"})

	endpoint := &models.Endpoint{
		Route:          "/admin/delete",
		Methods:        []models.HTTPMethod{models.MethodDELETE},
		Classification: models.ClassificationPublic,
		Authorization:  models.NewAuthorizationInfo(),
	}

	findings := engine.Evaluate(endpoint)

	// Should only have findings from AP001, not AP004, AP007, etc.
	for _, f := range findings {
		assert.Contains(t, []string{"AP001", "AP002"}, f.RuleID,
			"Unexpected rule %s in findings", f.RuleID)
	}
}
