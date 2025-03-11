package test

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtutil "github.com/marcotoldo/go-utils/jwt"
	"github.com/stretchr/testify/assert"
)

type CustomClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func TestSimpleParseJwt(t *testing.T) {
	testPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(testPrivateKeyPEM)
	if err != nil {
		log.Fatal(err.Error())
	}
	testPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(testPublicKeyPEM)
	if err != nil {
		log.Fatal(err.Error())
	}
	testPublicKeys := make(map[string]*rsa.PublicKey)
	testPublicKeys["foo"] = testPublicKey

	t.Run("should return error if kid is not known", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":   "1234567890",
			"name":  "John Doe",
			"admin": true,
			"exp":   time.Now().Add(time.Hour * 24).Unix(),
		})
		token.Header["kid"] = "bar"

		tokenString, err := token.SignedString(testPrivateKey)
		assert.Nil(t, err)

		_, err = jwtutil.DecodeClaimsJson(tokenString, &testPublicKeys)
		assert.ErrorContains(t, err, "unknown 'kid'")
	})

	t.Run("should return error if token has no exp and no iat", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":   "1234567890",
			"name":  "John Doe",
			"admin": true,
		})
		token.Header["kid"] = "foo"

		tokenString, err := token.SignedString(testPrivateKey)
		assert.Nil(t, err)

		_, err = jwtutil.DecodeClaimsJson(tokenString, &testPublicKeys)
		assert.ErrorContains(t, err, "invalid token, no ext, no iat")
	})

	t.Run("should return error if token expired (ext)", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":   "1234567890",
			"name":  "John Doe",
			"admin": true,
			"exp":   time.Now().Add(-time.Hour * 24).Unix(),
		})
		token.Header["kid"] = "foo"

		tokenString, err := token.SignedString(testPrivateKey)
		assert.Nil(t, err)

		_, err = jwtutil.DecodeClaimsJson(tokenString, &testPublicKeys)
		assert.ErrorContains(t, err, "expired")
	})

	t.Run("should return error if token expired (iat)", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":   "1234567890",
			"name":  "John Doe",
			"admin": true,
			"iat":   time.Now().Add(-time.Hour * 24).Unix(),
		})
		token.Header["kid"] = "foo"

		tokenString, err := token.SignedString(testPrivateKey)
		assert.Nil(t, err)

		_, err = jwtutil.DecodeClaimsJson(tokenString, &testPublicKeys)
		assert.ErrorContains(t, err, "expired")
	})

	t.Run("should return error if one or more claims are invalid", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":  "1234567890",
			"name": "John Doe",
			"role": 10, // should be string
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		token.Header["kid"] = "foo"

		tokenString, err := token.SignedString(testPrivateKey)
		assert.Nil(t, err)

		raw, err := jwtutil.DecodeClaimsJson(tokenString, &testPublicKeys)
		assert.Nil(t, err)

		var claims CustomClaims
		err = json.Unmarshal(*raw, &claims)
		assert.ErrorContains(t, err, "role")

	})

	t.Run("should parse the jwt", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":  "1234567890",
			"name": "John Doe",
			"role": "admin",
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		token.Header["kid"] = "foo"

		tokenString, err := token.SignedString(testPrivateKey)
		assert.Nil(t, err)

		raw, err := jwtutil.DecodeClaimsJson(tokenString, &testPublicKeys)
		assert.Nil(t, err)

		var claims CustomClaims
		err = json.Unmarshal(*raw, &claims)
		assert.Nil(t, err)
		assert.Equal(t, claims.Subject, "1234567890")
		assert.Equal(t, claims.Name, "John Doe")
		assert.Equal(t, claims.Role, "admin")
	})

}

var testPrivateKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAtRafKyXi7kkS
tT9qnYdb4SiMboKj51f0Rw77xavEhdPdzt81qnQt/ikCzadX5XjzpLGNTmCy+LT7
vowOGX03fPMh8pkGHdUnArjIujamFpS4bNSS2IcIduj+dffDBD7XMokdWgIklfhW
iNf9LRgwl5/EYfu5yxiK6lfIeD01Km71U2YsrbofroQ1sYhRhYTXPMbAefiV8nfW
P3EK26YiuckS1jnI4ebjSqyTkT/Dp4N4lOMij5O+xsaxdEgjYIwexUc1ASG7bkPX
0PKTVjuwVA1ZHfXjcGjTIz1yMJK9l2rqPDGKWuVa/dPvQoXEDFfJUvxzXQjtkrQu
qMGjkDnZAgMBAAECggEAK5xv16qsosw5Zk31YZvv56evhQR3dT9kRMiWB/2Gr213
8qEgG6WNMGFuB4/iGL66Xi0971Q3BxnI35YSXRiAoX+aCGs+HUfAFtmDVw3pUzIW
Cxy6CNeOy6gZd4jb/trlm874f9eAV6ZG8tJ6SvYbHNgblJZ2IOhpD/sTza8EbxTc
EMiTgy2m4Iyx5qTa1cwqusAmNqv/YO14A/sZhbNkbd7up4jH07JnLlDS9Jm2A3dB
8uFV9wbnfVpro1jVHyS0ApCSUrcD0Xdkmmz9iUoxffo7Pk1rfoxfRV+6mSt2obh2
ILyjKVLlwIoZxh57uAqfZ8jx6rUMR3hGgH50ZybZ+QKBgQDPvVUMzacOfOvDAnLF
48RasEHZY8iilktjT/OTK5cfGgqg02KGgDZXjZAeKk7zncQlA0tbo5zhIQtSG7TM
htGYisDH7XtGQpnVPZZZxaHFEM1avQailyYTrLUS21P4Fxrn0dyMXHb7tE654j1W
ed9Bis4Ra+Ct6wbO3swiNEVAlQKBgQDtecMxKr2xHM8WlRLXIVDtae1nd2QjH9rY
d6Pg079roNRuU4kmItKJTqJyflcCFqjf2X0OAoKiHFBqCL0D4B6H4osHJkpcDgsw
oazalCVIO4GIcQyRIm+RF3/9Be6wHopkZwrsbEKjKPpVy2QjSxFZn1YWMf2Re+VZ
XgiR6MSvNQKBgCSn19YGg6++wysJx467fe4yo6vkO4bU1kCT3vrc+jF2uuFd60io
Xu5cAE4SURQThoSxbB6jZA8lcYXvdZuRPnKYKSQd916SaeqCj4EPqlfHezTDneQa
n5FhLCJDqTFhglHdafkqZ6RKUInkLcaQgqBiCbJxQpftnKnsDkEK0B1xAoGAQYkG
yvzGmKggplTBfEkfckV3VMRoCCF0XaS2vwbwnp0lwsSe5r1ZaLcgsYQYMuVZ+Vyl
3EXpEx/JOVnr/7PL+SgVwgVZJApkICmd8DxOBZ8WYjcAhtUAAQSBN6x5cHUdMBQX
uaMuyKQ4YZDds7e1tAv6z+k/1vRgGMeQieO407kCgYEAwaC5lbVHtBX7eJTmIxkG
XTTA5wr4+HCHLS8kq11le0TBML9LdlCxaezJxCcxipNv8PbffErk0Bx8WoJXlBlS
GEehsDL1tvWKQDRAGYAdvyPV8MnTfLL2ko6ZzDDukFf2uNpZwmGwyQLL3qs2DfEF
4yLKkD6ABxAQhatbRzR7fMw=
-----END PRIVATE KEY-----`)

var testPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLUWnysl4u5JErU/ap2H
W+EojG6Co+dX9EcO+8WrxIXT3c7fNap0Lf4pAs2nV+V486SxjU5gsvi0+76MDhl9
N3zzIfKZBh3VJwK4yLo2phaUuGzUktiHCHbo/nX3wwQ+1zKJHVoCJJX4VojX/S0Y
MJefxGH7ucsYiupXyHg9NSpu9VNmLK26H66ENbGIUYWE1zzGwHn4lfJ31j9xCtum
IrnJEtY5yOHm40qsk5E/w6eDeJTjIo+TvsbGsXRII2CMHsVHNQEhu25D19Dyk1Y7
sFQNWR3143Bo0yM9cjCSvZdq6jwxilrlWv3T70KFxAxXyVL8c10I7ZK0LqjBo5A5
2QIDAQAB
-----END PUBLIC KEY-----`)
