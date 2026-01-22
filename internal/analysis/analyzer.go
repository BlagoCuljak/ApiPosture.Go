package analysis

import (
	"os"
	"path/filepath"
	"time"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/classification"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/config"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/discovery"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/rules"
)

// ProjectAnalyzer orchestrates the scanning process for a project.
type ProjectAnalyzer struct {
	config      *config.Config
	loader      *SourceLoader
	discoverers []discovery.Discoverer
	classifier  *classification.Classifier
	ruleEngine  *rules.Engine
}

// NewProjectAnalyzer creates a new ProjectAnalyzer.
func NewProjectAnalyzer(cfg *config.Config) *ProjectAnalyzer {
	if cfg == nil {
		cfg = config.NewConfig()
	}

	return &ProjectAnalyzer{
		config:      cfg,
		loader:      NewSourceLoader(),
		discoverers: discovery.AllDiscoverers(),
		classifier:  classification.NewClassifier(),
		ruleEngine:  rules.NewEngine(cfg.GetActiveRules()),
	}
}

// Analyze analyzes a project for API security issues.
func (a *ProjectAnalyzer) Analyze(path string) (*models.ScanResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	result := models.NewScanResult(absPath)

	// Get files to scan
	files, err := a.getFiles(absPath)
	if err != nil {
		return nil, err
	}
	result.FilesScanned = files

	// Scan each file
	for _, file := range files {
		a.scanFile(file, result)
	}

	// Classify all endpoints
	a.classifier.ClassifyAll(result.Endpoints)

	// Run security rules
	findings := a.ruleEngine.EvaluateAll(result.Endpoints)

	// Apply suppressions
	for _, finding := range findings {
		suppressed, reason := a.config.IsSuppressed(finding.RuleID, finding.Endpoint.FullRoute())
		if suppressed {
			finding.Suppressed = true
			finding.SuppressionReason = reason
		}
	}

	// Filter by rule enablement
	var enabledFindings []*models.Finding
	for _, f := range findings {
		if a.config.IsRuleEnabled(f.RuleID) {
			enabledFindings = append(enabledFindings, f)
		}
	}

	result.Findings = enabledFindings
	result.EndTime = time.Now()

	return result, nil
}

// getFiles returns the list of Go files to scan.
func (a *ProjectAnalyzer) getFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if filepath.Ext(path) == ".go" {
			return []string{path}, nil
		}
		return []string{}, nil
	}

	return GetGoFiles(path, a.config.ExcludePatterns)
}

// scanFile scans a single file for endpoints.
func (a *ProjectAnalyzer) scanFile(filePath string, result *models.ScanResult) {
	source, errStr := a.loader.TryParseFile(filePath)
	if errStr != "" {
		result.ParseErrors[filePath] = errStr
		return
	}

	// Try each discoverer
	for _, disc := range a.discoverers {
		if disc.CanHandle(source) {
			result.FrameworksDetected[disc.Framework()] = true

			endpoints, err := disc.Discover(source)
			if err != nil {
				continue
			}

			result.Endpoints = append(result.Endpoints, endpoints...)
		}
	}
}
