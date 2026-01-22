// Package version contains version information for ApiPosture.
package version

// Version information, set at build time via ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info returns the version info as a string.
func Info() string {
	return Version
}

// FullInfo returns the full version info including commit and build date.
func FullInfo() string {
	return "apiposture version " + Version + " (commit: " + Commit + ", built: " + BuildDate + ")"
}
