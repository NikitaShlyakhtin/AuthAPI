package data

import (
	"authapi/internal/validator"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	RefreshLength int
}

var (
	ErrTokenExpired = errors.New("token has expired")
	ErrTokenInvalid = errors.New("token is invalid")
)

func ValidateRefreshToken(v *validator.Validator, token string, size int) {
	v.Check(len(token) == size, "refresh_token", fmt.Sprintf("must be %d bytes long", size))
}

func (tokens *Tokens) Generate(user User, cfg TokenConfig) error {
	claims := &jwt.MapClaims{
		"sub":      user.ID,
		"exp":      jwt.TimeFunc().Add(cfg.AccessExpiry).Unix(),
		"username": user.Username,
		"email":    user.Email,
	}

	accessToken, err := GenerateAccessToken(cfg.AccessSecret, claims)
	if err != nil {
		return err
	}

	tokens.AccessToken = accessToken

	refreshToken, err := GenerateRefreshToken(cfg.RefreshLength)
	if err != nil {
		return err
	}

	tokens.RefreshToken = refreshToken

	return nil
}

func GenerateAccessToken(secret string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return ss, nil
}

func GenerateRefreshToken(size int) (string, error) {
	rb := make([]byte, size*3/4)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}

	token := base64.StdEncoding.EncodeToString(rb)
	return token[:size], nil
}

func HashRefreshToken(token, secret string) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func ParseAccessToken(accessToken string, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil {
		switch {
		case err.(*jwt.ValidationError).Errors == jwt.ValidationErrorExpired:
			return nil, ErrTokenExpired
		default:
			return nil, err
		}
	}

	return token, nil
}
