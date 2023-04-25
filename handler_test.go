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
	middleware := NewJWTMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), secret)

	t.Run("Missing Authorization header", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)

		middleware.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Missing Authorization header", w.Body.String())
	})

	t.Run("Invalid JWT token", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer invalidtoken")

		middleware.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Invalid JWT token", w.Body.String())
	})

	t.Run("Valid JWT token", func(t *testing.T) {
		w := httptest.NewRecorder()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		})
		tokenString, _ := token.SignedString([]byte(secret))

		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tokenString)

		middleware.ServeHTTP(w, r)

		assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	})
}

