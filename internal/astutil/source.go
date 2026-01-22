// Package astutil provides AST utilities and shared types for Go source analysis.
package astutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

// ParsedSource represents a parsed Go source file.
type ParsedSource struct {
	// FilePath is the path to the source file.
	FilePath string

	// FileSet is the token file set.
	FileSet *token.FileSet

	// AST is the parsed AST.
	AST *ast.File

	// Content is the raw source content.
	Content string

	// Imports maps import paths to their aliases.
	Imports map[string]string
}

// SourceLoader handles loading and parsing Go source files.
type SourceLoader struct {
	fileSet *token.FileSet
}

// NewSourceLoader creates a new SourceLoader.
func NewSourceLoader() *SourceLoader {
	return &SourceLoader{
		fileSet: token.NewFileSet(),
	}
}

// ParseFile parses a Go source file.
func (l *SourceLoader) ParseFile(path string) (*ParsedSource, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return l.ParseContent(path, string(content))
}

// ParseContent parses Go source code from a string.
func (l *SourceLoader) ParseContent(path, content string) (*ParsedSource, error) {
	f, err := parser.ParseFile(l.fileSet, path, content, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	source := &ParsedSource{
		FilePath: path,
		FileSet:  l.fileSet,
		AST:      f,
		Content:  content,
		Imports:  make(map[string]string),
	}

	// Extract imports
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Use last part of path as default alias
			parts := strings.Split(importPath, "/")
			alias = parts[len(parts)-1]
		}
		source.Imports[importPath] = alias
	}

	return source, nil
}

// TryParseFile attempts to parse a file, returning nil and error string on failure.
func (l *SourceLoader) TryParseFile(path string) (*ParsedSource, string) {
	source, err := l.ParseFile(path)
	if err != nil {
		return nil, err.Error()
	}
	return source, ""
}

// HasImport checks if the source has a specific import path.
func (s *ParsedSource) HasImport(importPath string) bool {
	_, ok := s.Imports[importPath]
	return ok
}

// HasImportPrefix checks if the source has any import with the given prefix.
func (s *ParsedSource) HasImportPrefix(prefix string) bool {
	for importPath := range s.Imports {
		if strings.HasPrefix(importPath, prefix) {
			return true
		}
	}
	return false
}

// GetImportAlias returns the alias for an import path, or empty string if not found.
func (s *ParsedSource) GetImportAlias(importPath string) string {
	return s.Imports[importPath]
}
