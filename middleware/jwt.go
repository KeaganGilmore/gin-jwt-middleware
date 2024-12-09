// middleware/jwt.go
package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type JWTConfig struct {
	Secret         []byte
	ContextKey     string
	HeaderKey      string
	TokenPrefix    string
	RequiredClaims []string
}

func JWTAuthMiddleware(cfg JWTConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(cfg.HeaderKey)
		if authHeader == "" {
			log.Println("Missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, cfg.TokenPrefix)
		if tokenString == authHeader {
			log.Printf("Missing token prefix: %s\n", cfg.TokenPrefix)
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Missing token prefix: %s", cfg.TokenPrefix)})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return cfg.Secret, nil
		})

		if err != nil || !token.Valid {
			log.Printf("Invalid token: %v\n", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Println("Invalid token claims")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		for _, rc := range cfg.RequiredClaims {
			if _, exists := claims[rc]; !exists {
				log.Printf("Missing required claim: %s\n", rc)
				c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Missing required claim: %s", rc)})
				c.Abort()
				return
			}
		}

		log.Println("Token validated successfully")
		c.Set(cfg.ContextKey, map[string]interface{}(claims))
		c.Next()
	}
}
