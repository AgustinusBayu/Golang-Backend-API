package models

import "github.com/dgrijalva/jwt-go"

const ValidKeyword = ":enc-valid"

type TokenClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Users struct {
	UserID   string `json:"user_id,omitempty" bson:"user_id"`
	UserName string `json:"user_name,omitempty" bson:"user_name"`
	Password string `json:"password,omitempty" bson:"password"`
}

type RequestEncrypt struct {
	Text     string `json:"text"`
	Password string `json:"password"`
}

type RequestDecrypt struct {
	Text     string `json:"text"`
	Password string `json:"password"`
}
