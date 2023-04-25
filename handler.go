package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"github.com/traefik/yaegi/stdlib/unsafe"
)

// JWTMiddleware is the JWT authentication middleware structure.
type JWTMiddleware struct {
	Next   http.Handler
	Secret string
}

// NewJWTMiddleware creates a new JWT authentication middleware.
func NewJWTMiddleware(next http.Handler, secret string) *JWTMiddleware {
	return &JWTMiddleware{Next: next, Secret: secret}
}

// ServeHTTP handles the JWT authentication for the request.
func (j *JWTMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	header := req.Header.Get("Authorization")
	if header == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("Missing Authorization header"))
		return
	}

	tokenString := strings.TrimPrefix(header, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(j.Secret), nil
	})

	if err != nil || !token.Valid {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("Invalid JWT token"))
		return
	}

	// Check if the token has expired
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("Invalid JWT claims"))
		return
	}

	expiration, ok := claims["exp"].(float64)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("Invalid JWT expiration"))
		return
	}

	if time.Now().Unix() > int64(expiration) {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("JWT token has expired"))
		return
	}

	j.Next.ServeHTTP(rw, req)
}

func main() {
	i := interp.New(interp.Options{})
	_ = i.Use(stdlib.Symbols)
	_ = i.Use(unsafe.Symbols)

	_, err := i.Eval(`import "fmt"`)

	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	_, err = i.EvalWithContext(ctx, `fmt.Println("Hello, JWT Middleware!")`)

	if err != nil {
		panic(err)
	}
}
