package main

import (
	"github.com/KeaganGilmore/gin-jwt-middleware/middleware"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	r := gin.Default()

	jwtConfig := middleware.JWTConfig{
		Secret:         []byte("example-secret-key"),
		ContextKey:     "userClaims",
		HeaderKey:      "Authorization",
		TokenPrefix:    "Bearer ",
		RequiredClaims: []string{"id", "roleID"},
	}

	r.Use(middleware.JWTAuthMiddleware(jwtConfig))

	conditionConfig := middleware.ConditionConfig{
		ContextKey: "userClaims",
		Check: func(claims map[string]interface{}) bool {
			if claims["roleID"] == nil {
				return false
			}
			roleVal, ok := claims["roleID"].(float64)
			if !ok {
				return false
			}
			return int(roleVal) >= 10
		},
	}

	r.GET("/admin", middleware.ConditionMiddleware(conditionConfig), func(c *gin.Context) {
		user := c.MustGet("userClaims").(map[string]interface{})
		c.JSON(http.StatusOK, gin.H{"message": "admin access", "user": user})
	})

	r.Run(":8080")
}
