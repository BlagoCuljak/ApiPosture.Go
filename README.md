# ApiPosture.Go

API security inspection tool for Go applications. Performs static source-code analysis using Go's `go/ast` module to identify authorization misconfigurations and security risks in Go API frameworks.

## Supported Frameworks

- **Gin** - `github.com/gin-gonic/gin`
- **Echo** - `github.com/labstack/echo/v4`
- **Chi** - `github.com/go-chi/chi/v5`
- **Fiber** - `github.com/gofiber/fiber/v2`
- **net/http** - Standard library

## Installation

### From Source

```bash
go install github.com/BlagoCuljak/ApiPosture.Go/cmd/apiposture@latest
```

### From Binary

Download the latest release from the [releases page](https://github.com/BlagoCuljak/ApiPosture.Go/releases).

### Homebrew (macOS/Linux)

```bash
brew install BlagoCuljak/tap/apiposture
```

## Quick Start

```bash
# Scan current directory
apiposture scan .

# Scan specific directory
apiposture scan ./path/to/project

# Output as JSON
apiposture scan ./path --output json

# Output as Markdown
apiposture scan ./path --output markdown --output-file report.md

# Only report high severity and above
apiposture scan ./path --severity high

# Exit with error code if high+ findings
apiposture scan ./path --fail-on high

# Scan sample applications (for testing)
apiposture scan ./samples/gin_app
apiposture scan ./samples/echo_app
```

## Security Rules

| Rule | Name | Severity | Trigger |
|------|------|----------|---------|
| AP001 | Public without explicit intent | HIGH | Public endpoint without explicit AllowAny |
| AP002 | AllowAnonymous on write | HIGH | AllowAny on POST/PUT/DELETE/PATCH |
| AP003 | Group/route auth conflict | MEDIUM | Route AllowAny overrides group auth |
| AP004 | Missing auth on writes | CRITICAL | Public POST/PUT/PATCH/DELETE |
| AP005 | Excessive role access | LOW | >3 roles on single endpoint |
| AP006 | Weak role naming | LOW | Generic roles like "user", "admin" |
| AP007 | Sensitive route keywords | MEDIUM | admin/debug/export in public routes |
| AP008 | Endpoint without auth | HIGH | No auth configuration at all |

## Configuration

Create `.apiposture.yaml` in your project root:

```yaml
rules:
  enabled: []      # Empty = all rules
  disabled:
    - AP006        # Disable specific rules

include:
  - "**/*.go"

exclude:
  - "**/vendor/**"
  - "**/*_test.go"
  - "**/testdata/**"

suppressions:
  - rule: AP001
    route: "/health.*"
    reason: "Health check is intentionally public"
  - rule: AP007
    route: "/debug/pprof.*"
    reason: "Profiling endpoints protected at infrastructure level"

min_severity: info
```

## CLI Options

```
Usage:
  apiposture scan [path] [flags]

Flags:
  -c, --config string         Configuration file (.apiposture.yaml)
      --classification strings Filter by security classification
      --fail-on string        Exit with code 1 if findings at this severity or above
      --framework strings     Filter by framework
      --group-by string       Group results by field (file, classification, rule, framework)
  -h, --help                  help for scan
      --method strings        Filter by HTTP method
      --no-color              Disable colored output
      --no-icons              Disable icons in output
  -o, --output string         Output format (terminal, json, markdown) (default "terminal")
  -f, --output-file string    Write output to file
      --route-contains string Filter routes containing substring
      --rule strings          Filter by rule ID (e.g., AP001)
      --severity string       Minimum severity to report (info, low, medium, high, critical) (default "info")
      --sort-by string        Sort results by field (severity, route, method, classification) (default "severity")
      --sort-dir string       Sort direction (asc, desc) (default "desc")
```

## Example Output

```
────────────────────────────────────────────────────────────
ApiPosture Security Scan
Path: /path/to/project
────────────────────────────────────────────────────────────

Files scanned: 15
Frameworks: gin
Endpoints: 12
Findings: 2 critical, 3 high, 1 medium

Security Findings
────────────────────────────────────────────────────────────
Sev  Rule     Route                     Method   Message
--------------------------------------------------------------------------------
!!   AP004    /api/users                POST     Write endpoint '/api/users' [POST] has no authentication
!    AP007    /admin/dashboard          GET      Public route '/admin/dashboard' contains sensitive keywords: admin
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run ApiPosture
  run: |
    go install github.com/BlagoCuljak/ApiPosture.Go/cmd/apiposture@latest
    apiposture scan . --fail-on high
```

### GitLab CI

```yaml
security-scan:
  script:
    - go install github.com/BlagoCuljak/ApiPosture.Go/cmd/apiposture@latest
    - apiposture scan . --output json --output-file apiposture-report.json
    - apiposture scan . --fail-on high
  artifacts:
    paths:
      - apiposture-report.json
```

## Development

```bash
# Clone the repository
git clone https://github.com/BlagoCuljak/ApiPosture.Go.git
cd ApiPosture.Go

# Install dependencies
make deps

# Run tests
make test

# Run linter
make lint

# Build
make build

# Run against sample apps
make run-sample-gin
make run-sample-echo
```

## License

MIT License - see [LICENSE](LICENSE) for details.
