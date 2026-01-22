// Sample Gin application for testing ApiPosture
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Public endpoints (will trigger findings)
	r.GET("/health", healthCheck)
	r.GET("/api/v1/public", publicEndpoint)

	// Public write endpoint (will trigger AP004)
	r.POST("/api/v1/feedback", submitFeedback)

	// Admin routes without auth (will trigger AP007, AP008)
	r.GET("/admin/dashboard", adminDashboard)
	r.DELETE("/admin/users/:id", deleteUser)

	// Protected routes with auth middleware
	api := r.Group("/api/v1")
	api.Use(AuthMiddleware())
	{
		api.GET("/users", listUsers)
		api.GET("/users/:id", getUser)
		api.POST("/users", createUser)
		api.PUT("/users/:id", updateUser)
		api.DELETE("/users/:id", deleteUserAPI)
	}

	// Admin routes with role middleware
	admin := r.Group("/api/v1/admin")
	admin.Use(AuthMiddleware(), RoleMiddleware("admin"))
	{
		admin.GET("/stats", getStats)
		admin.POST("/config", updateConfig)
	}

	r.Run(":8080")
}

// Middleware functions
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check JWT token
		token := c.GetHeader("Authorization")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func RoleMiddleware(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check user role
		c.Next()
	}
}

// Handler functions
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func publicEndpoint(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "public data"})
}

func submitFeedback(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "feedback received"})
}

func adminDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"dashboard": "admin"})
}

func deleteUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func listUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"users": []string{}})
}

func getUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"user": "data"})
}

func createUser(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"user": "created"})
}

func updateUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"user": "updated"})
}

func deleteUserAPI(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func getStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"stats": "data"})
}

func updateConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"config": "updated"})
}
