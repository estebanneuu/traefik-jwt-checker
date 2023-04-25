package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWTMiddleware(t *testing.T) {
	secret := "testsecret"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	t.Run("Valid JWT token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "1234567890",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		})

		tokenString, _ := token.SignedString([]byte(secret))

		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Add("Authorization", "Bearer "+tokenString)

		w := httptest.NewRecorder()
		middleware := NewJWTMiddleware(handler, secret)
		middleware.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Missing Authorization header", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)

		w := httptest.NewRecorder()
		middleware := NewJWTMiddleware(handler, secret)
		middleware.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Invalid JWT token", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Add("Authorization", "Bearer invalid-token")

		w := httptest.NewRecorder()
		middleware := NewJWTMiddleware(handler, secret)
		middleware.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Expired JWT token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "1234567890",
			"exp": float64(time.Now().Add(-time.Hour).Unix()),
		})

		tokenString, _ := token.SignedString([]byte(secret))

		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Add("Authorization", "Bearer "+tokenString)

		w := httptest.NewRecorder()
		middleware := NewJWTMiddleware(handler, secret)
		middleware.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
