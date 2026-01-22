package models

// AuthorizationInfo contains authorization information for an endpoint.
type AuthorizationInfo struct {
	// RequiresAuth indicates whether the endpoint requires authentication.
	RequiresAuth bool `json:"requires_auth"`

	// AllowsAnonymous indicates whether the endpoint explicitly allows anonymous access.
	AllowsAnonymous bool `json:"allows_anonymous"`

	// Roles contains required roles (e.g., ["admin", "moderator"]).
	Roles []string `json:"roles,omitempty"`

	// Scopes contains required scopes (e.g., ["read:users", "write:users"]).
	Scopes []string `json:"scopes,omitempty"`

	// Permissions contains required permissions (e.g., ["IsAuthenticated", "IsAdminUser"]).
	Permissions []string `json:"permissions,omitempty"`

	// Policies contains required policies (e.g., ["AdminPolicy"]).
	Policies []string `json:"policies,omitempty"`

	// AuthDependencies contains auth dependencies (middleware, decorators).
	AuthDependencies []string `json:"auth_dependencies,omitempty"`

	// Inherited indicates whether auth is inherited from parent (router, group, etc.).
	Inherited bool `json:"inherited"`

	// Source indicates the source of the authorization (e.g., "class", "method", "router").
	Source string `json:"source,omitempty"`
}

// NewAuthorizationInfo creates a new AuthorizationInfo with default values.
func NewAuthorizationInfo() AuthorizationInfo {
	return AuthorizationInfo{
		Roles:            []string{},
		Scopes:           []string{},
		Permissions:      []string{},
		Policies:         []string{},
		AuthDependencies: []string{},
	}
}

// HasSpecificRequirements returns true if there are specific role/scope/permission requirements.
func (a *AuthorizationInfo) HasSpecificRequirements() bool {
	return len(a.Roles) > 0 || len(a.Scopes) > 0 || len(a.Permissions) > 0 || len(a.Policies) > 0
}

// IsPublic returns true if the endpoint is effectively public.
func (a *AuthorizationInfo) IsPublic() bool {
	return a.AllowsAnonymous || (!a.RequiresAuth && !a.HasSpecificRequirements())
}

// Merge merges authorization info from a parent (e.g., group-level to route-level).
// If override is true, child values take precedence when both are set.
func (a *AuthorizationInfo) Merge(other AuthorizationInfo, override bool) AuthorizationInfo {
	if override && other.AllowsAnonymous {
		// AllowAnonymous at method level overrides group-level auth
		return AuthorizationInfo{
			AllowsAnonymous: true,
			Inherited:       false,
			Source:          other.Source,
		}
	}

	// Check if other (child) has any meaningful auth configuration
	otherHasConfig := other.RequiresAuth || other.AllowsAnonymous ||
		len(other.Roles) > 0 || len(other.Scopes) > 0 ||
		len(other.Permissions) > 0 || len(other.Policies) > 0 ||
		len(other.AuthDependencies) > 0

	// For allows_anonymous: if override is true and child has no config, inherit from parent
	var allowsAnon bool
	if override {
		if otherHasConfig {
			allowsAnon = other.AllowsAnonymous
		} else {
			allowsAnon = a.AllowsAnonymous
		}
	} else {
		allowsAnon = a.AllowsAnonymous && other.AllowsAnonymous
	}

	// Determine inherited flag
	inherited := a.Inherited
	if other.RequiresAuth {
		inherited = false
	}

	// Determine source
	source := other.Source
	if source == "" {
		source = a.Source
	}

	return AuthorizationInfo{
		RequiresAuth:     a.RequiresAuth || other.RequiresAuth,
		AllowsAnonymous:  allowsAnon,
		Roles:            mergeStringSlices(a.Roles, other.Roles),
		Scopes:           mergeStringSlices(a.Scopes, other.Scopes),
		Permissions:      mergeStringSlices(a.Permissions, other.Permissions),
		Policies:         mergeStringSlices(a.Policies, other.Policies),
		AuthDependencies: mergeStringSlices(a.AuthDependencies, other.AuthDependencies),
		Inherited:        inherited,
		Source:           source,
	}
}

// mergeStringSlices merges two string slices, removing duplicates.
func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}
