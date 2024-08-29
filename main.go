package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type signin struct {
	// ID       string  `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	// Price    float64 `json:"price"`
}

var status = "JWT"

func doLogin(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, status)
}

func main() {
	router := gin.Default()
	router.POST("/auth", doLogin)
	router.POST("/signin", signIn)
	router.GET("/welcome", welcome)
	router.GET("/refresh", refresh)

	router.Run("localhost:8080")
}

// Define the secret key used for signing the JWT.
var jwtKey = []byte("my_secret_key")

// User represents the structure for an authenticated user.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims will be encoded into the JWT.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// signIn handles the authentication process.
func signIn(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// In a real application, you'd verify the user against a database.
	if user.Username != "admin" || user.Password != "password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create the JWT claims, including the username and expiry time.
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Sign the JWT with the secret key.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	// Return the token.
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// welcome handles requests to a protected endpoint.
func welcome(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Welcome " + claims.Username})
}

// refresh generates a new JWT token for a valid one.
func refresh(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Generate a new token with a refreshed expiration time.
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = newToken.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}
