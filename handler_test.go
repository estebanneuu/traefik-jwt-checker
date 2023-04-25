package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

const testSecret = "test-secret"

func TestJWTMiddleware_ValidToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	middleware := NewJWTMiddleware(next, testSecret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	tokenString, _ := token.SignedString([]byte(testSecret))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "OK", recorder.Body.String())
}

func TestJWTMiddleware_MissingToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	middleware := NewJWTMiddleware(next, testSecret)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Missing Authorization header", recorder.Body.String())
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	middleware := NewJWTMiddleware(next, testSecret)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+"invalid-token")

	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Invalid JWT token", recorder.Body.String())
}
