package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

func TestGinDiscoverer_CanHandle(t *testing.T) {
	discoverer := NewGinDiscoverer()
	loader := astutil.NewSourceLoader()

	tests := []struct {
		name     string
		code     string
		expected bool
	}{
		{
			name: "has gin import",
			code: `package main

import "github.com/gin-gonic/gin"

func main() {}`,
			expected: true,
		},
		{
			name: "no gin import",
			code: `package main

import "net/http"

func main() {}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := loader.ParseContent("test.go", tt.code)
			require.NoError(t, err)

			result := discoverer.CanHandle(source)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGinDiscoverer_Discover(t *testing.T) {
	discoverer := NewGinDiscoverer()
	loader := astutil.NewSourceLoader()

	code := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	r.GET("/users", listUsers)
	r.POST("/users", createUser)
	r.PUT("/users/:id", updateUser)
	r.DELETE("/users/:id", deleteUser)
}

func listUsers(c *gin.Context) {}
func createUser(c *gin.Context) {}
func updateUser(c *gin.Context) {}
func deleteUser(c *gin.Context) {}
`

	source, err := loader.ParseContent("test.go", code)
	require.NoError(t, err)

	endpoints, err := discoverer.Discover(source)
	require.NoError(t, err)

	assert.Len(t, endpoints, 4)

	// Verify routes and methods using route+method as key
	type routeMethod struct {
		route  string
		method models.HTTPMethod
	}
	found := make(map[routeMethod]bool)
	for _, e := range endpoints {
		require.Len(t, e.Methods, 1)
		found[routeMethod{e.Route, e.Methods[0]}] = true
		assert.Equal(t, models.FrameworkGin, e.Framework)
	}

	assert.True(t, found[routeMethod{"/users", models.MethodGET}])
	assert.True(t, found[routeMethod{"/users", models.MethodPOST}])
	assert.True(t, found[routeMethod{"/users/:id", models.MethodPUT}])
	assert.True(t, found[routeMethod{"/users/:id", models.MethodDELETE}])
}

func TestGinDiscoverer_DiscoverWithGroups(t *testing.T) {
	discoverer := NewGinDiscoverer()
	loader := astutil.NewSourceLoader()

	code := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	api := r.Group("/api/v1")
	api.GET("/users", listUsers)
	api.POST("/users", createUser)

	admin := r.Group("/admin", authMiddleware)
	admin.GET("/stats", getStats)
}

func listUsers(c *gin.Context) {}
func createUser(c *gin.Context) {}
func getStats(c *gin.Context) {}
func authMiddleware(c *gin.Context) {}
`

	source, err := loader.ParseContent("test.go", code)
	require.NoError(t, err)

	endpoints, err := discoverer.Discover(source)
	require.NoError(t, err)

	assert.Len(t, endpoints, 3)

	// Check that api endpoints have correct prefix
	for _, e := range endpoints {
		if e.Route == "/users" {
			assert.Equal(t, "/api/v1", e.RouterPrefix)
		}
		if e.Route == "/stats" {
			assert.Equal(t, "/admin", e.RouterPrefix)
		}
	}
}

func TestGinDiscoverer_DiscoverWithMiddleware(t *testing.T) {
	discoverer := NewGinDiscoverer()
	loader := astutil.NewSourceLoader()

	code := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	r.GET("/public", publicHandler)
	r.GET("/protected", authMiddleware, protectedHandler)

	api := r.Group("/api", jwtAuth)
	api.GET("/data", dataHandler)
}

func publicHandler(c *gin.Context) {}
func protectedHandler(c *gin.Context) {}
func dataHandler(c *gin.Context) {}
func authMiddleware(c *gin.Context) {}
func jwtAuth(c *gin.Context) {}
`

	source, err := loader.ParseContent("test.go", code)
	require.NoError(t, err)

	endpoints, err := discoverer.Discover(source)
	require.NoError(t, err)

	assert.Len(t, endpoints, 3)

	// Find protected endpoint and verify it has auth
	for _, e := range endpoints {
		if e.Route == "/protected" {
			assert.True(t, e.Authorization.RequiresAuth || len(e.Authorization.AuthDependencies) > 0,
				"Protected endpoint should have auth")
		}
	}
}
