# README.md

# gin-jwt-middleware

A flexible JWT authentication and role-based authorization middleware for [Gin](https://github.com/gin-gonic/gin).

## Features

- Extracts JWT from the `Authorization` header (Bearer token).
- Validates token signature against a configurable secret.
- Optionally extracts claims and places them into the context.
- Role-based route protection using custom role IDs.
- Easily integrates into any Gin application.

## Usage

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/KeaganGilmore/gin-jwt-middleware/middleware"
)

func main() {
    r := gin.Default()

    // Setup middleware with config
    jwtConfig := middleware.JWTConfig{
        Secret:       []byte("your-secret-key"),
        ContextKey:   "user",
        HeaderKey:    "Authorization",
        TokenPrefix:  "Bearer ",
        RequiredClaims: []string{"id", "roleID"},
    }
    r.Use(middleware.JWTAuthMiddleware(jwtConfig))

    // Protected route
    r.GET("/admin", middleware.RoleMiddleware(10), func(c *gin.Context) {
        user := c.MustGet("userClaims").(map[string]interface{})
        c.JSON(200, gin.H{"message": "Welcome Admin", "user": user})
    })

    r.Run(":8080")
}
