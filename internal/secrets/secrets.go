// Package secrets implements AP201, detection of hardcoded provider secrets.
//
// Only high-precision, provider-prefixed patterns are used. Generic
// heuristics (password=, token=, Bearer, JWT, connection strings) are
// intentionally excluded because they produce too many false positives.
package secrets

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RuleID is the identifier of the hardcoded secret rule.
const RuleID = "AP201"

// RuleName is the human-readable name of the rule.
const RuleName = "Hardcoded secret"

// Recommendation is the remediation advice attached to every finding.
const Recommendation = "Remove the secret from source, rotate it, and load it from an environment variable or a secret manager."

// Match is a detected secret. Value is already redacted.
type Match struct {
	FilePath string
	Line     int
	Type     string
	Redacted string
}

type pattern struct {
	name string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{"AWS access key ID", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GCP API key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b`)},
	{"GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{82}\b`)},
	{"GitLab personal access token", regexp.MustCompile(`\bglpat-[0-9A-Za-z\-_]{20,}\b`)},
	{"Stripe live secret key", regexp.MustCompile(`\b(sk|rk)_live_[0-9A-Za-z]{24,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)},
	{"Slack webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24}`)},
	{"SendGrid API key", regexp.MustCompile(`\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`)},
	{"npm token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"DigitalOcean token", regexp.MustCompile(`\bdop_v1_[0-9a-f]{64}\b`)},
	{"PEM private key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----`)},
}

const pemType = "PEM private key"

var placeholderMarkers = []string{
	"example", "xxxx", "your_", "your-", "<", ">", "${", "{{",
	"changeme", "dummy", "fake", "sample", "placeholder", "redacted",
}

// skipDirs are directory names (case-insensitive) that are never scanned.
var skipDirs = map[string]bool{
	"test": true, "tests": true, "spec": true, "__tests__": true,
	"fixtures": true, "testdata": true, "samples": true, "examples": true,
	"docs": true, "node_modules": true, "vendor": true, ".git": true,
}

// scannedExts are the extensions (besides .env files) that are scanned.
var scannedExts = map[string]bool{
	".go": true, ".yml": true, ".yaml": true, ".json": true, ".properties": true,
}

const (
	maxFileSize = 1 << 20
	maxLineLen  = 10000
)

// IsPlaceholder reports whether a matched value looks like a placeholder.
func IsPlaceholder(value string) bool {
	v := strings.ToLower(value)
	for _, m := range placeholderMarkers {
		if strings.Contains(v, m) {
			return true
		}
	}
	return false
}

// Redact returns the first 4 characters of a secret followed by an ellipsis.
func Redact(value string) string {
	r := []rune(value)
	if len(r) > 4 {
		r = r[:4]
	}
	return string(r) + "…"
}

// IsSkippedDir reports whether a directory name is excluded from scanning.
func IsSkippedDir(name string) bool {
	return skipDirs[strings.ToLower(name)]
}

// IsTestFile reports whether a file name follows a test-file convention.
func IsTestFile(name string) bool {
	base := filepath.Base(name)
	lower := strings.ToLower(base)
	switch {
	case strings.HasSuffix(base, "_test.go"),
		strings.HasSuffix(base, "Test.java"), strings.HasSuffix(base, "Tests.java"),
		strings.HasSuffix(base, "Tests.cs"), strings.HasSuffix(base, "Test.cs"),
		strings.HasSuffix(base, "Test.php"),
		strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"),
		strings.HasSuffix(base, "_test.py"):
		return true
	}
	for _, ext := range []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(lower, ".test"+ext) || strings.HasSuffix(lower, ".spec"+ext) {
			return true
		}
	}
	return false
}

// IsExcludedPath reports whether a path (relative to the scan root) lies in
// an excluded directory or is a test file.
func IsExcludedPath(relPath string) bool {
	slashed := filepath.ToSlash(relPath)
	parts := strings.Split(slashed, "/")
	for _, p := range parts[:len(parts)-1] {
		if IsSkippedDir(p) {
			return true
		}
	}
	return IsTestFile(slashed)
}

// IsScannableFile reports whether a file name is a source or config file
// that should be scanned. Lockfiles and minified files are rejected.
func IsScannableFile(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if strings.HasSuffix(base, ".lock") || base == "go.sum" ||
		base == "package-lock.json" || base == "npm-shrinkwrap.json" ||
		strings.Contains(base, ".min.") {
		return false
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	return scannedExts[filepath.Ext(base)]
}

// ScanContent scans text and returns one match per (line, secret type).
// The path is only used to populate the result.
func ScanContent(path, content string) []Match {
	var matches []Match
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 4*maxLineLen)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if len(line) > maxLineLen {
			continue
		}
		for _, p := range patterns {
			for _, m := range p.re.FindAllString(line, -1) {
				if IsPlaceholder(m) {
					continue
				}
				red := Redact(m)
				if p.name == pemType {
					red = "-----…"
				}
				matches = append(matches, Match{FilePath: path, Line: lineNo, Type: p.name, Redacted: red})
				break // one finding per (file, line, type)
			}
		}
	}
	return matches
}

// ScanFile reads and scans a single file, honoring the file-level guards.
// rel is the path relative to the scan root, used for exclusion checks.
func ScanFile(path, rel string) []Match {
	if IsExcludedPath(rel) || !IsScannableFile(path) {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxFileSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ScanContent(path, string(data))
}

// ScanDir walks root and scans every eligible file. shouldExclude is an
// optional extra filter (e.g. user exclude patterns) given the relative path.
func ScanDir(root string, shouldExclude func(rel, abs string) bool) []Match {
	var all []Match
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if d.IsDir() {
			if rel != "." && IsSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldExclude != nil && shouldExclude(rel, path) {
			return nil
		}
		all = append(all, ScanFile(path, rel)...)
		return nil
	})
	return all
}
