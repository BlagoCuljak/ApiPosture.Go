package rules

import (
	"fmt"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

const maxRolesThreshold = 3

// AP005ExcessiveRoles flags endpoints with too many roles.
type AP005ExcessiveRoles struct{}

// NewAP005ExcessiveRoles creates a new AP005 rule.
func NewAP005ExcessiveRoles() *AP005ExcessiveRoles {
	return &AP005ExcessiveRoles{}
}

// ID returns the rule ID.
func (r *AP005ExcessiveRoles) ID() string {
	return "AP005"
}

// Name returns the rule name.
func (r *AP005ExcessiveRoles) Name() string {
	return "Excessive role access"
}

// Severity returns the rule severity.
func (r *AP005ExcessiveRoles) Severity() models.Severity {
	return models.SeverityLow
}

// Description returns the rule description.
func (r *AP005ExcessiveRoles) Description() string {
	return fmt.Sprintf("Endpoint allows access to more than %d roles. "+
		"Consider using broader permission categories.", maxRolesThreshold)
}

// Evaluate checks if endpoint has too many roles.
func (r *AP005ExcessiveRoles) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	roles := endpoint.Authorization.Roles

	if len(roles) <= maxRolesThreshold {
		return nil
	}

	return []*models.Finding{
		createFinding(r, endpoint,
			fmt.Sprintf("Endpoint '%s' allows access to %d roles: %s",
				endpoint.FullRoute(), len(roles), strings.Join(roles, ", ")),
			"Consider grouping roles into broader permission categories or using policies",
		),
	}
}
