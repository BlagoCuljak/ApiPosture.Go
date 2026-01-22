// Package analysis provides AST parsing and analysis for Go source files.
package analysis

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
)

// Re-export types from astutil for backward compatibility
type ParsedSource = astutil.ParsedSource
type SourceLoader = astutil.SourceLoader

// NewSourceLoader creates a new SourceLoader.
func NewSourceLoader() *SourceLoader {
	return astutil.NewSourceLoader()
}

// GetGoFiles returns all .go files in a directory (recursively).
func GetGoFiles(root string, excludePatterns []string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Check if directory should be excluded
			for _, pattern := range excludePatterns {
				if matched, _ := filepath.Match(pattern, info.Name()); matched {
					return filepath.SkipDir
				}
				// Also check for **/ patterns
				if strings.HasPrefix(pattern, "**/") {
					subPattern := strings.TrimPrefix(pattern, "**/")
					if strings.HasSuffix(subPattern, "/**") {
						dirPattern := strings.TrimSuffix(subPattern, "/**")
						if info.Name() == dirPattern {
							return filepath.SkipDir
						}
					}
				}
			}
			return nil
		}

		// Only include .go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Check exclude patterns
		relPath, _ := filepath.Rel(root, path)
		for _, pattern := range excludePatterns {
			if matchPattern(pattern, relPath, path) {
				return nil
			}
		}

		files = append(files, path)
		return nil
	})

	return files, err
}

// matchPattern checks if a path matches an exclude pattern.
func matchPattern(pattern, relPath, absPath string) bool {
	// Handle **/ prefix
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")

		// Handle **/*_test.go style patterns
		if strings.HasPrefix(suffix, "*") {
			suffix = strings.TrimPrefix(suffix, "*")
			return strings.HasSuffix(relPath, suffix) || strings.HasSuffix(absPath, suffix)
		}

		// Handle **/dirname/** style patterns
		if strings.HasSuffix(suffix, "/**") {
			dirName := strings.TrimSuffix(suffix, "/**")
			return strings.Contains(relPath, dirName+string(filepath.Separator)) ||
				strings.Contains(relPath, string(filepath.Separator)+dirName+string(filepath.Separator))
		}

		return strings.HasSuffix(relPath, suffix)
	}

	// Direct match
	if matched, _ := filepath.Match(pattern, relPath); matched {
		return true
	}

	if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
		return true
	}

	return false
}
