package rules

import (
	"fmt"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// weakRoleNames contains generic role names that should be more specific.
var weakRoleNames = map[string]bool{
	"user":     true,
	"users":    true,
	"admin":    true,
	"admins":   true,
	"guest":    true,
	"guests":   true,
	"member":   true,
	"members":  true,
	"default":  true,
	"basic":    true,
	"standard": true,
	"normal":   true,
	"regular":  true,
}

// AP006WeakRoleNaming flags endpoints with generic role names.
type AP006WeakRoleNaming struct{}

// NewAP006WeakRoleNaming creates a new AP006 rule.
func NewAP006WeakRoleNaming() *AP006WeakRoleNaming {
	return &AP006WeakRoleNaming{}
}

// ID returns the rule ID.
func (r *AP006WeakRoleNaming) ID() string {
	return "AP006"
}

// Name returns the rule name.
func (r *AP006WeakRoleNaming) Name() string {
	return "Weak role naming"
}

// Severity returns the rule severity.
func (r *AP006WeakRoleNaming) Severity() models.Severity {
	return models.SeverityLow
}

// Description returns the rule description.
func (r *AP006WeakRoleNaming) Description() string {
	return "Role names are too generic. " +
		"Consider using more descriptive names that indicate specific permissions."
}

// Evaluate checks for weak role names.
func (r *AP006WeakRoleNaming) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	roles := endpoint.Authorization.Roles

	var weak []string
	for _, role := range roles {
		if weakRoleNames[strings.ToLower(role)] {
			weak = append(weak, role)
		}
	}

	if len(weak) == 0 {
		return nil
	}

	return []*models.Finding{
		createFinding(r, endpoint,
			fmt.Sprintf("Endpoint '%s' uses generic role names: %s",
				endpoint.FullRoute(), strings.Join(weak, ", ")),
			"Use more descriptive role names that indicate permissions, e.g., 'billing_admin', 'content_editor', 'report_viewer'",
		),
	}
}
