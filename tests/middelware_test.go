// tests/middleware_test.go
package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KeaganGilmore/gin-jwt-middleware/middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":     "12345",
		"roleID": 10,
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	r := gin.Default()
	r.Use(middleware.JWTAuthMiddleware(middleware.JWTConfig{
		Secret:         secret,
		ContextKey:     "userClaims",
		HeaderKey:      "Authorization",
		TokenPrefix:    "Bearer ",
		RequiredClaims: []string{"id", "roleID"},
	}))
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConditionMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":     "12345",
		"roleID": 1,
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	r := gin.Default()
	r.Use(middleware.JWTAuthMiddleware(middleware.JWTConfig{
		Secret:         secret,
		ContextKey:     "userClaims",
		HeaderKey:      "Authorization",
		TokenPrefix:    "Bearer ",
		RequiredClaims: []string{"id", "roleID"},
	}))
	r.GET("/admin", middleware.ConditionMiddleware(middleware.ConditionConfig{
		ContextKey: "userClaims",
		Check: func(claims map[string]interface{}) bool {
			roleVal, ok := claims["roleID"].(float64)
			if !ok {
				return false
			}
			return int(roleVal) >= 10
		},
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin"})
	})

	req, _ := http.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
