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

		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tokenString)

		rr := httptest.NewRecorder()

		jwtMiddleware := NewJWTMiddleware(handler, secret)
		jwtMiddleware.ServeHTTP(rr, r)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "OK", rr.Body.String())
	})

	t.Run("Missing Authorization header", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)

		rr := httptest.NewRecorder()

		jwtMiddleware := NewJWTMiddleware(handler, secret)
		jwtMiddleware.ServeHTTP(rr, r)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "Missing Authorization header", rr.Body.String())
	})

	t.Run("Invalid JWT token", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer invalid-token")

		rr := httptest.NewRecorder()

		jwtMiddleware := NewJWTMiddleware(handler, secret)
		jwtMiddleware.ServeHTTP(rr, r)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "Invalid JWT token", rr.Body.String())
	})

	t.Run("Expired JWT token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "1234567890",
			"exp": float64(time.Now().Add(-time.Hour).Unix()),
		})

		tokenString, _ := token.SignedString([]byte(secret))

		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tokenString)

		rr := httptest.NewRecorder()

		jwtMiddleware := NewJWTMiddleware(handler, secret)
		jwtMiddleware.ServeHTTP(rr, r)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "JWT token has expired", rr.Body.String())
	})
}
