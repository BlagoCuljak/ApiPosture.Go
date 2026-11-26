package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/config"
)

func setupSecretProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	secret := "gh" + "p_" + strings.Repeat("a", 36)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\nvar k = \""+secret+"\"\n"), 0o600))
	return dir
}

func TestAP201Reported(t *testing.T) {
	dir := setupSecretProject(t)
	res, err := NewProjectAnalyzer(config.NewConfig()).Analyze(dir)
	require.NoError(t, err)
	require.Len(t, res.Findings, 1)
	f := res.Findings[0]
	assert.Equal(t, "AP201", f.RuleID)
	assert.Equal(t, "high", strings.ToLower(string(f.Severity)))
	assert.Equal(t, 2, f.Endpoint.LineNumber)
	assert.Contains(t, f.Message, "ghp_…")
	assert.NotContains(t, f.Message, strings.Repeat("a", 10))
}

func TestAP201Disabled(t *testing.T) {
	dir := setupSecretProject(t)
	cfg := config.NewConfig()
	cfg.Rules.Disabled = []string{"AP201"}
	res, err := NewProjectAnalyzer(cfg).Analyze(dir)
	require.NoError(t, err)
	assert.Empty(t, res.Findings)
}

func TestAP201NotInEnabledList(t *testing.T) {
	dir := setupSecretProject(t)
	cfg := config.NewConfig()
	cfg.Rules.Enabled = []string{"AP001"}
	res, err := NewProjectAnalyzer(cfg).Analyze(dir)
	require.NoError(t, err)
	assert.Empty(t, res.Findings)
}

func TestAP201Suppressed(t *testing.T) {
	dir := setupSecretProject(t)
	cfg := config.NewConfig()
	cfg.Suppressions = []config.SuppressionConfig{{RuleID: "AP201", RoutePattern: `main\.go`, Reason: "test"}}
	res, err := NewProjectAnalyzer(cfg).Analyze(dir)
	require.NoError(t, err)
	require.Len(t, res.Findings, 1)
	assert.True(t, res.Findings[0].Suppressed)
}
