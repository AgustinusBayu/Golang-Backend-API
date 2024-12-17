package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"golang-api/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func InitPrivateKey(filename string) error {
	keyData, err := os.ReadFile(filename)

	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyData)

	if block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("kunci privat tidak valid")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	privateKey = privKey.(*rsa.PrivateKey)
	return nil
}

func InitPublicKey(filename string) error {
	keyData, err := os.ReadFile(filename)

	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyData)

	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("kunci publik tidak valid")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	publicKey = pubKey.(*rsa.PublicKey)
	return nil
}

func GenerateToken(username string) (string, error) {
	claims := models.TokenClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func TokenValid(c *gin.Context) (string, error) {
	tokenString := c.GetHeader("Authorization")

	if tokenString == "" {
		return "", errors.New("Token not found")
	}

	tokenString = tokenString[len("Bearer "):]

	claims := &models.TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		return "", err
	}

	return claims.Username, nil
}
