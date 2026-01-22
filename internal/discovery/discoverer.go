// Package discovery provides endpoint discovery for various Go API frameworks.
package discovery

import (
	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// Discoverer is the interface for framework endpoint discovery.
type Discoverer interface {
	// Framework returns the framework this discoverer handles.
	Framework() models.Framework

	// CanHandle returns true if this discoverer can handle the given source.
	CanHandle(source *astutil.ParsedSource) bool

	// Discover finds all endpoints in the given source file.
	Discover(source *astutil.ParsedSource) ([]*models.Endpoint, error)
}

// AllDiscoverers returns all available discoverers.
func AllDiscoverers() []Discoverer {
	return []Discoverer{
		NewGinDiscoverer(),
		NewEchoDiscoverer(),
		NewChiDiscoverer(),
		NewFiberDiscoverer(),
		NewNetHTTPDiscoverer(),
	}
}
