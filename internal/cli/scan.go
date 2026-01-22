package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/analysis"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/config"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/output"
)

// Scan command options
var (
	outputFormat   string
	outputFile     string
	configFile     string
	severity       string
	failOn         string
	sortBy         string
	sortDir        string
	classification []string
	methods        []string
	routeContains  string
	frameworks     []string
	rules          []string
	groupBy        string
	noColor        bool
	noIcons        bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a Go project for API security issues",
	Long: `Scan analyzes Go source files for API endpoints and evaluates them
against security rules to identify potential authorization misconfigurations.

Examples:
  apiposture scan ./                           # Scan current directory
  apiposture scan ./path/to/project           # Scan specific directory
  apiposture scan ./path --output json        # Output as JSON
  apiposture scan ./path --severity high      # Only report high+ severity
  apiposture scan ./path --fail-on high       # Exit 1 if high+ findings`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "terminal", "Output format (terminal, json, markdown)")
	scanCmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Write output to file")
	scanCmd.Flags().StringVarP(&configFile, "config", "c", "", "Configuration file (.apiposture.yaml)")
	scanCmd.Flags().StringVar(&severity, "severity", "info", "Minimum severity to report (info, low, medium, high, critical)")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 1 if findings at this severity or above")
	scanCmd.Flags().StringVar(&sortBy, "sort-by", "severity", "Sort results by field (severity, route, method, classification)")
	scanCmd.Flags().StringVar(&sortDir, "sort-dir", "desc", "Sort direction (asc, desc)")
	scanCmd.Flags().StringSliceVar(&classification, "classification", nil, "Filter by security classification")
	scanCmd.Flags().StringSliceVar(&methods, "method", nil, "Filter by HTTP method")
	scanCmd.Flags().StringVar(&routeContains, "route-contains", "", "Filter routes containing substring")
	scanCmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Filter by framework")
	scanCmd.Flags().StringSliceVar(&rules, "rule", nil, "Filter by rule ID (e.g., AP001)")
	scanCmd.Flags().StringVar(&groupBy, "group-by", "", "Group results by field (file, classification, rule, framework)")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	scanCmd.Flags().BoolVar(&noIcons, "no-icons", false, "Disable icons in output")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine path to scan
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Check path exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("path not found: %s", path)
	}

	// Load configuration
	var cfg *config.Config
	if configFile != "" {
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		// Try to find config file
		if info.IsDir() {
			configPath := config.FindConfig(path)
			if configPath != "" {
				cfg, err = config.LoadConfig(configPath)
				if err != nil {
					return fmt.Errorf("failed to load config: %w", err)
				}
			}
		}
	}

	if cfg == nil {
		cfg = config.NewConfig()
	}

	// Run analysis
	analyzer := analysis.NewProjectAnalyzer(cfg)
	result, err := analyzer.Analyze(path)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Filter findings by minimum severity
	minSeverity := models.ParseSeverity(severity)
	filterFindingsBySeverity(result, minSeverity)

	// Apply additional filters
	applyFilters(result)

	// Sort findings
	sortFindings(result)

	// Create formatter
	opts := output.FormatterOptions{
		NoColor: noColor,
		NoIcons: noIcons,
		GroupBy: groupBy,
	}

	var formatter output.Formatter
	switch outputFormat {
	case "json":
		formatter = output.NewJSONFormatter(opts)
	case "markdown":
		formatter = output.NewMarkdownFormatter(opts)
	default:
		formatter = output.NewTerminalFormatter(opts)
	}

	// Format and output
	out, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("formatting failed: %w", err)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(out), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Output written to %s\n", outputFile)
	} else {
		fmt.Print(out)
	}

	// Exit with error code if findings at fail-on severity
	if failOn != "" {
		failSeverity := models.ParseSeverity(failOn)
		if len(result.FindingsAtOrAbove(failSeverity)) > 0 {
			os.Exit(1)
		}
	}

	return nil
}

func filterFindingsBySeverity(result *models.ScanResult, minSeverity models.Severity) {
	filtered := make([]*models.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if f.Severity.GreaterOrEqual(minSeverity) {
			filtered = append(filtered, f)
		}
	}
	result.Findings = filtered
}

func applyFilters(result *models.ScanResult) {
	// Filter by classification
	if len(classification) > 0 {
		classSet := make(map[string]bool)
		for _, c := range classification {
			classSet[strings.ToLower(c)] = true
		}

		filtered := make([]*models.Endpoint, 0)
		for _, e := range result.Endpoints {
			if classSet[string(e.Classification)] {
				filtered = append(filtered, e)
			}
		}
		result.Endpoints = filtered

		filteredFindings := make([]*models.Finding, 0)
		for _, f := range result.Findings {
			if classSet[string(f.Endpoint.Classification)] {
				filteredFindings = append(filteredFindings, f)
			}
		}
		result.Findings = filteredFindings
	}

	// Filter by method
	if len(methods) > 0 {
		methodSet := make(map[string]bool)
		for _, m := range methods {
			methodSet[strings.ToUpper(m)] = true
		}

		filtered := make([]*models.Endpoint, 0)
		for _, e := range result.Endpoints {
			for _, m := range e.Methods {
				if methodSet[string(m)] {
					filtered = append(filtered, e)
					break
				}
			}
		}
		result.Endpoints = filtered

		filteredFindings := make([]*models.Finding, 0)
		for _, f := range result.Findings {
			for _, m := range f.Endpoint.Methods {
				if methodSet[string(m)] {
					filteredFindings = append(filteredFindings, f)
					break
				}
			}
		}
		result.Findings = filteredFindings
	}

	// Filter by route
	if routeContains != "" {
		filtered := make([]*models.Endpoint, 0)
		for _, e := range result.Endpoints {
			if strings.Contains(e.FullRoute(), routeContains) {
				filtered = append(filtered, e)
			}
		}
		result.Endpoints = filtered

		filteredFindings := make([]*models.Finding, 0)
		for _, f := range result.Findings {
			if strings.Contains(f.Endpoint.FullRoute(), routeContains) {
				filteredFindings = append(filteredFindings, f)
			}
		}
		result.Findings = filteredFindings
	}

	// Filter by framework
	if len(frameworks) > 0 {
		frameworkSet := make(map[string]bool)
		for _, f := range frameworks {
			frameworkSet[strings.ToLower(f)] = true
		}

		filtered := make([]*models.Endpoint, 0)
		for _, e := range result.Endpoints {
			if frameworkSet[string(e.Framework)] {
				filtered = append(filtered, e)
			}
		}
		result.Endpoints = filtered

		filteredFindings := make([]*models.Finding, 0)
		for _, f := range result.Findings {
			if frameworkSet[string(f.Endpoint.Framework)] {
				filteredFindings = append(filteredFindings, f)
			}
		}
		result.Findings = filteredFindings
	}

	// Filter by rule
	if len(rules) > 0 {
		ruleSet := make(map[string]bool)
		for _, r := range rules {
			ruleSet[strings.ToUpper(r)] = true
		}

		filteredFindings := make([]*models.Finding, 0)
		for _, f := range result.Findings {
			if ruleSet[f.RuleID] {
				filteredFindings = append(filteredFindings, f)
			}
		}
		result.Findings = filteredFindings
	}
}

func sortFindings(result *models.ScanResult) {
	reverse := sortDir == "desc"

	sort.Slice(result.Findings, func(i, j int) bool {
		var less bool

		switch sortBy {
		case "severity":
			less = result.Findings[i].Severity.Order() < result.Findings[j].Severity.Order()
		case "route":
			less = result.Findings[i].Endpoint.FullRoute() < result.Findings[j].Endpoint.FullRoute()
		case "method":
			less = result.Findings[i].Endpoint.DisplayMethods() < result.Findings[j].Endpoint.DisplayMethods()
		case "classification":
			less = string(result.Findings[i].Endpoint.Classification) < string(result.Findings[j].Endpoint.Classification)
		default:
			less = result.Findings[i].Severity.Order() < result.Findings[j].Severity.Order()
		}

		if reverse {
			return !less
		}
		return less
	})
}
