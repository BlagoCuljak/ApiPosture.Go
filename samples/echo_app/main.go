// Sample Echo application for testing ApiPosture
package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus: true,
		LogURI:    true,
		LogMethod: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			return nil
		},
	}))
	e.Use(middleware.Recover())

	// Public endpoints (will trigger findings)
	e.GET("/health", healthCheck)
	e.GET("/api/v1/public", publicEndpoint)

	// Public write endpoint (will trigger AP004)
	e.POST("/api/v1/feedback", submitFeedback)

	// Debug endpoints (will trigger AP007)
	e.GET("/debug/vars", debugVars)
	e.GET("/internal/metrics", internalMetrics)

	// Protected routes with JWT middleware
	api := e.Group("/api/v1")
	api.Use(JWTMiddleware())
	api.GET("/users", listUsers)
	api.GET("/users/:id", getUser)
	api.POST("/users", createUser)
	api.PUT("/users/:id", updateUser)
	api.DELETE("/users/:id", deleteUser)

	// Admin routes with role middleware
	admin := e.Group("/api/v1/admin")
	admin.Use(JWTMiddleware())
	admin.Use(RoleMiddleware("admin"))
	admin.GET("/stats", getStats)
	admin.POST("/config", updateConfig)
	admin.DELETE("/cache", clearCache)

	e.Logger.Fatal(e.Start(":8080"))
}

// Middleware functions
func JWTMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := c.Request().Header.Get("Authorization")
			if token == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			return next(c)
		}
	}
}

func RoleMiddleware(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check user role
			return next(c)
		}
	}
}

// Handler functions
func healthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "healthy"})
}

func publicEndpoint(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"message": "public data"})
}

func submitFeedback(c echo.Context) error {
	return c.JSON(http.StatusCreated, map[string]string{"message": "feedback received"})
}

func debugVars(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"debug": "vars"})
}

func internalMetrics(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"metrics": "data"})
}

func listUsers(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"users": []string{}})
}

func getUser(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"user": "data"})
}

func createUser(c echo.Context) error {
	return c.JSON(http.StatusCreated, map[string]interface{}{"user": "created"})
}

func updateUser(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"user": "updated"})
}

func deleteUser(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"deleted": true})
}

func getStats(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"stats": "data"})
}

func updateConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"config": "updated"})
}

func clearCache(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{"cache": "cleared"})
}
