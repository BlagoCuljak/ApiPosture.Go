// Package licensing provides license management for ApiPosture Pro features.
package licensing

import "errors"

// Manager handles license validation and Pro feature access.
type Manager struct {
	isLicensed bool
}

// NewManager creates a new licensing manager.
func NewManager() *Manager {
	return &Manager{
		isLicensed: false,
	}
}

// Status returns the current license status.
func (m *Manager) Status() string {
	if m.isLicensed {
		return "License: Active (Pro)"
	}
	return "License: Community Edition (Free)\n\nUpgrade to Pro for additional features:\n  - Team collaboration\n  - Custom rules\n  - Priority support\n\nVisit https://apiposture.dev/pricing for more information."
}

// Activate attempts to activate a license key.
func (m *Manager) Activate(key string) error {
	// Stub: always fails in community edition
	return errors.New("license activation is not available in the community edition")
}

// IsLicensed returns true if a Pro license is active.
func (m *Manager) IsLicensed() bool {
	return m.isLicensed
}

// HasFeature checks if a Pro feature is available.
func (m *Manager) HasFeature(feature string) bool {
	// Community edition has no Pro features
	return false
}
