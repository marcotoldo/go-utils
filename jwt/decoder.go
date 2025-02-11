package jwtutil

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// returned raw bytes can be then unmarshaled into the expected custom claims type
func DecodeClaimsJson(tokenString string, publicKeys *map[string]*rsa.PublicKey) (*[]byte, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		tokenKid, exists := token.Header["kid"]
		if !exists {
			return nil, errors.New("missing header 'kid'")
		}
		pubKey, exists := (*publicKeys)[tokenKid.(string)]
		if !exists {
			return nil, errors.New("unknown 'kid'")
		}
		// Ensure the token method is what we expect (RSA)
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}
	if expiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	jsonData, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return &jsonData, nil
}
