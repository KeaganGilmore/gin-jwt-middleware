// middleware/condition.go
package middleware

import (
	"log"
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
			log.Println("No claims found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No claims found in context"})
			c.Abort()
			return
		}

		userClaims, ok := claims.(map[string]interface{})
		if !ok {
			log.Println("Invalid claims format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid claims format"})
			c.Abort()
			return
		}

		if !cfg.Check(userClaims) {
			log.Println("Access condition not met")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access condition not met"})
			c.Abort()
			return
		}

		log.Println("Access condition met")
		c.Next()
	}
}
