// middleware/condition.go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ConditionConfig struct {
	ContextKey string
	Check      func(claims map[string]interface{}) bool
}

func ConditionMiddleware(cfg ConditionConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get(cfg.ContextKey)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No claims found in context"})
			c.Abort()
			return
		}

		userClaims, ok := claims.(map[string]interface{})
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid claims format"})
			c.Abort()
			return
		}

		if !cfg.Check(userClaims) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access condition not met"})
			c.Abort()
			return
		}

		c.Next()
	}
}
