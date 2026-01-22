// Package config handles YAML configuration loading for ApiPosture.
package config

import (
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// SuppressionConfig contains configuration for suppressing specific findings.
type SuppressionConfig struct {
	RuleID       string `yaml:"rule"`
	RoutePattern string `yaml:"route"`
	Reason       string `yaml:"reason"`
}

// Matches returns true if this suppression matches a finding.
func (s *SuppressionConfig) Matches(ruleID, route string) bool {
	if s.RuleID != ruleID && s.RuleID != "*" {
		return false
	}

	if s.RoutePattern != "" {
		re, err := regexp.Compile(s.RoutePattern)
		if err != nil {
			// Invalid regex, treat as literal match
			return route == s.RoutePattern || contains(route, s.RoutePattern)
		}
		if !re.MatchString(route) {
			return false
		}
	}

	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Config contains the full configuration for ApiPosture.
type Config struct {
	// Rules configuration
	Rules RulesConfig `yaml:"rules"`

	// Include patterns for files to scan
	IncludePatterns []string `yaml:"include"`

	// Exclude patterns for files to skip
	ExcludePatterns []string `yaml:"exclude"`

	// Suppressions for specific findings
	Suppressions []SuppressionConfig `yaml:"suppressions"`

	// AuthPatterns contains custom auth dependency patterns
	AuthPatterns []string `yaml:"auth_patterns"`

	// MinSeverity is the minimum severity to report
	MinSeverity string `yaml:"min_severity"`
}

// RulesConfig contains rule enablement configuration.
type RulesConfig struct {
	Enabled  []string `yaml:"enabled"`
	Disabled []string `yaml:"disabled"`
}

// NewConfig creates a new Config with default values.
func NewConfig() *Config {
	return &Config{
		IncludePatterns: []string{"**/*.go"},
		ExcludePatterns: []string{
			"**/vendor/**",
			"**/*_test.go",
			"**/testdata/**",
			"**/.git/**",
			"**/node_modules/**",
		},
		MinSeverity: "info",
	}
}

// GetActiveRules returns list of active rules (nil = all).
func (c *Config) GetActiveRules() []string {
	if len(c.Rules.Enabled) > 0 {
		result := make([]string, 0, len(c.Rules.Enabled))
		disabled := make(map[string]bool)
		for _, r := range c.Rules.Disabled {
			disabled[r] = true
		}
		for _, r := range c.Rules.Enabled {
			if !disabled[r] {
				result = append(result, r)
			}
		}
		return result
	}
	return nil
}

// IsRuleEnabled returns true if a rule is enabled.
func (c *Config) IsRuleEnabled(ruleID string) bool {
	if len(c.Rules.Enabled) > 0 {
		found := false
		for _, r := range c.Rules.Enabled {
			if r == ruleID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, r := range c.Rules.Disabled {
		if r == ruleID {
			return false
		}
	}

	return true
}

// IsSuppressed checks if a finding should be suppressed.
// Returns (is_suppressed, reason).
func (c *Config) IsSuppressed(ruleID, route string) (bool, string) {
	for _, s := range c.Suppressions {
		if s.Matches(ruleID, route) {
			return true, s.Reason
		}
	}
	return false, ""
}

// LoadConfig loads configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := NewConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Apply defaults if not specified
	if len(config.IncludePatterns) == 0 {
		config.IncludePatterns = []string{"**/*.go"}
	}

	return config, nil
}

// FindConfig looks for a configuration file starting from the given path.
// Returns the path to the config file if found, or empty string if not.
func FindConfig(startPath string) string {
	configNames := []string{".apiposture.yaml", ".apiposture.yml", "apiposture.yaml", "apiposture.yml"}

	current, err := filepath.Abs(startPath)
	if err != nil {
		return ""
	}

	// If it's a file, start from its directory
	info, err := os.Stat(current)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		current = filepath.Dir(current)
	}

	for {
		for _, name := range configNames {
			configPath := filepath.Join(current, name)
			if _, err := os.Stat(configPath); err == nil {
				return configPath
			}
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return ""
}
