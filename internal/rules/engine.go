package rules

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// Engine evaluates security rules against endpoints.
type Engine struct {
	rules        []Rule
	enabledRules map[string]bool
}

// NewEngine creates a new rule engine.
// If enabledRules is nil, all rules are enabled.
func NewEngine(enabledRules []string) *Engine {
	allRules := []Rule{
		NewAP001PublicWithoutIntent(),
		NewAP002AnonymousOnWrite(),
		NewAP003AuthConflict(),
		NewAP004MissingAuthWrites(),
		NewAP005ExcessiveRoles(),
		NewAP006WeakRoleNaming(),
		NewAP007SensitiveKeywords(),
		NewAP008EndpointWithoutAuth(),
	}

	engine := &Engine{
		rules: allRules,
	}

	if enabledRules != nil {
		engine.enabledRules = make(map[string]bool)
		for _, id := range enabledRules {
			engine.enabledRules[id] = true
		}
	}

	return engine
}

// Rules returns all available rules.
func (e *Engine) Rules() []Rule {
	return e.rules
}

// Evaluate evaluates all enabled rules against an endpoint.
func (e *Engine) Evaluate(endpoint *models.Endpoint) []*models.Finding {
	var findings []*models.Finding

	for _, rule := range e.rules {
		if e.enabledRules != nil && !e.enabledRules[rule.ID()] {
			continue
		}

		ruleFindings := rule.Evaluate(endpoint)
		findings = append(findings, ruleFindings...)
	}

	return findings
}

// EvaluateAll evaluates all enabled rules against all endpoints.
func (e *Engine) EvaluateAll(endpoints []*models.Endpoint) []*models.Finding {
	var findings []*models.Finding

	for _, endpoint := range endpoints {
		findings = append(findings, e.Evaluate(endpoint)...)
	}

	return findings
}

// GetRule returns a rule by its ID.
func (e *Engine) GetRule(ruleID string) Rule {
	for _, rule := range e.rules {
		if rule.ID() == ruleID {
			return rule
		}
	}
	return nil
}
