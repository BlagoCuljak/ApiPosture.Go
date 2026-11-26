package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rep(c string, n int) string { return strings.Repeat(c, n) }

// Secrets are assembled at runtime so no literal token appears in the repo.
func truePositives() map[string]string {
	return map[string]string{
		"AWS access key ID":            "AK" + "IA" + "QWERTYUIOPASDFGH",
		"GCP API key":                  "AI" + "za" + rep("a", 35),
		"GitHub token":                 "gh" + "p_" + rep("a", 36),
		"GitHub fine-grained token":    "github" + "_pat_" + rep("A", 82),
		"GitLab personal access token": "gl" + "pat-" + rep("a", 20),
		"Stripe live secret key":       "sk" + "_live_" + rep("a", 24),
		"Slack token":                  "xo" + "xb-" + rep("1", 12),
		"Slack webhook":                "https://hooks." + "slack.com/services/T" + rep("A", 9) + "/B" + rep("B", 9) + "/" + rep("c", 24),
		"SendGrid API key":             "S" + "G." + rep("a", 22) + "." + rep("b", 43),
		"npm token":                    "np" + "m_" + rep("a", 36),
		"DigitalOcean token":           "do" + "p_v1_" + rep("a", 64),
		"PEM private key":              "-----BEGIN " + "RSA PRIVATE KEY-----",
	}
}

func TestTruePositives(t *testing.T) {
	for typ, secret := range truePositives() {
		t.Run(typ, func(t *testing.T) {
			ms := ScanContent("cfg.go", "package x\nconst k = \""+secret+"\"\n")
			require.Len(t, ms, 1)
			assert.Equal(t, typ, ms[0].Type)
			assert.Equal(t, 2, ms[0].Line)
			assert.Equal(t, "cfg.go", ms[0].FilePath)
		})
	}
}

func TestOtherGitHubPrefixesAndStripeRestricted(t *testing.T) {
	for _, s := range []string{
		"gh" + "o_" + rep("a", 36), "gh" + "u_" + rep("a", 36),
		"gh" + "s_" + rep("a", 36), "gh" + "r_" + rep("a", 36),
		"rk" + "_live_" + rep("a", 30), "AS" + "IA" + "QWERTYUIOPASDFGH",
	} {
		assert.Len(t, ScanContent("a.go", "x := \""+s+"\""), 1, s[:4])
	}
}

func TestRedactionNeverLeaksSecret(t *testing.T) {
	secret := "gh" + "p_" + rep("a", 36)
	ms := ScanContent("a.go", "x := \""+secret+"\"")
	require.Len(t, ms, 1)
	assert.Equal(t, "ghp_…", ms[0].Redacted)
	assert.NotContains(t, ms[0].Redacted, rep("a", 5))
}

func TestOneFindingPerLineAndType(t *testing.T) {
	s := "gh" + "p_" + rep("a", 36)
	ms := ScanContent("a.go", s+" "+s+"\n"+s)
	assert.Len(t, ms, 2)
	assert.Equal(t, 1, ms[0].Line)
	assert.Equal(t, 2, ms[1].Line)
}

func TestPlaceholdersSkipped(t *testing.T) {
	cases := []string{
		"AK" + "IAIOSFODNN7EXAMPLE",
		"gh" + "p_" + rep("X", 36),
		"gh" + "p_" + "your_" + rep("a", 31),
		"gh" + "p_" + "changeme" + rep("a", 28),
		"gh" + "p_" + "dummy" + rep("a", 31),
		"gh" + "p_" + "FAKE" + rep("a", 32),
		"gh" + "p_" + "sample" + rep("a", 30),
		"gh" + "p_" + "placeholder" + rep("a", 25),
		"gh" + "p_" + "redacted" + rep("a", 28),
		"xo" + "xb-" + "your-token-here-123",
		"gl" + "pat-" + "your-" + rep("a", 20),
		"sk" + "_live_" + "example" + rep("a", 24),
	}
	for _, c := range cases {
		assert.Empty(t, ScanContent("a.go", "v = \""+c+"\""), c)
	}
}

func TestNegatives(t *testing.T) {
	cases := []string{
		`password = "hunter2hunter2"`,
		`api_key = "abcdefghijklmnop1234"`,
		`token: "abcdefghijklmnopqrstuvwxyz"`,
		"pk" + "_live_" + rep("a", 30), // publishable key is public
		"Authorization: Bearer " + rep("a", 40),
		"postgres://user:pass@localhost/db",
		"AK" + "IA" + "SHORT",
		"-----BEGIN " + "CERTIFICATE-----",
		"-----BEGIN " + "PUBLIC KEY-----",
		"my_gh" + "p_" + rep("a", 36), // no word boundary
	}
	for _, c := range cases {
		assert.Empty(t, ScanContent("a.go", c), c)
	}
}

func TestPEMVariants(t *testing.T) {
	for _, v := range []string{"", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "} {
		assert.Len(t, ScanContent("k.yaml", "-----BEGIN "+v+"PRIVATE KEY-----"), 1, v)
	}
	assert.Len(t, ScanContent("k.yaml", "-----BEGIN PGP "+"PRIVATE KEY BLOCK-----"), 1)
}

func TestTestFileConventions(t *testing.T) {
	for _, f := range []string{
		"a_test.go", "FooTest.java", "FooTests.cs", "a.test.ts", "a.spec.ts",
		"a.test.js", "b.spec.tsx", "test_a.py", "a_test.py", "src/x/FooTests.cs",
	} {
		assert.True(t, IsTestFile(f), f)
	}
	for _, f := range []string{"main.go", "config.yaml", "latest.py", "contest.go"} {
		assert.False(t, IsTestFile(f), f)
	}
}

func TestExcludedPaths(t *testing.T) {
	for _, p := range []string{
		"test/a.go", "tests/a.yaml", "spec/a.json", "__tests__/a.json",
		"fixtures/a.yaml", "x/testdata/a.json", "samples/a.go", "examples/a.go",
		"docs/a.yaml", "node_modules/p/a.json", "vendor/m/a.go", "a/b/c_test.go",
	} {
		assert.True(t, IsExcludedPath(p), p)
	}
	for _, p := range []string{"main.go", "cmd/app/config.yaml", ".env", "internal/x.go"} {
		assert.False(t, IsExcludedPath(p), p)
	}
}

func TestScannableFiles(t *testing.T) {
	for _, f := range []string{"a.go", ".env", ".env.production", "a.yml", "a.yaml", "a.json", "a.properties", "appsettings.Production.json"} {
		assert.True(t, IsScannableFile(f), f)
	}
	for _, f := range []string{"go.sum", "package-lock.json", "yarn.lock", "Cargo.lock", "app.min.js", "app.min.json", "a.txt", "a.md"} {
		assert.False(t, IsScannableFile(f), f)
	}
}

func TestScanDir(t *testing.T) {
	dir := t.TempDir()
	secret := "gh" + "p_" + rep("a", 36)
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}
	write("main.go", "package main\nvar k = \""+secret+"\"\n")
	write(".env", "TOKEN="+secret+"\n")
	write("config/app.yaml", "token: "+secret+"\n")
	write("main_test.go", "var k = \""+secret+"\"\n")
	write("testdata/a.json", `{"k":"`+secret+`"}`)
	write("vendor/x/a.go", "var k = \""+secret+"\"\n")
	write("package-lock.json", `{"k":"`+secret+`"}`)
	write("readme.txt", secret)

	ms := ScanDir(dir, nil)
	var rels []string
	for _, m := range ms {
		r, _ := filepath.Rel(dir, m.FilePath)
		rels = append(rels, filepath.ToSlash(r))
	}
	assert.ElementsMatch(t, []string{"main.go", ".env", "config/app.yaml"}, rels)
}
