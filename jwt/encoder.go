package jwtutil

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

func Encode(claims *jwt.MapClaims, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
