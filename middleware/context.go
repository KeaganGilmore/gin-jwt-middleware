// middleware/context.go
package middleware

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

func GetClaimAsString(c *gin.Context, contextKey, claimKey string) (string, bool) {
	claims, exists := c.Get(contextKey)
	if !exists {
		return "", false
	}
	userClaims, ok := claims.(map[string]interface{})
	if !ok {
		return "", false
	}
	val, exists := userClaims[claimKey]
	if !exists {
		return "", false
	}
	switch v := val.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	default:
		return "", false
	}
}
