package data

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type TokenModel struct {
	DB *sql.DB
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var (
	ErrTokenExpired = errors.New("token has expired")
)

func (m TokenModel) GenerateNewPair(user User, secret string, accessExpiry, refreshExpiry time.Duration) (Tokens, error) {
	var tokens Tokens

	claims := &jwt.MapClaims{
		"sub":      user.ID,
		"exp":      jwt.TimeFunc().Add(accessExpiry).Unix(),
		"username": user.Username,
		"email":    user.Email,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := accessToken.SignedString([]byte(secret))
	if err != nil {
		return tokens, err
	}

	tokens.AccessToken = ss

	rb := make([]byte, 32)
	_, err = rand.Read(rb)
	if err != nil {
		return tokens, err
	}

	tokens.RefreshToken = base64.StdEncoding.EncodeToString(rb)
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(tokens.RefreshToken), 12)
	if err != nil {
		return tokens, err
	}

	query := `
		INSERT INTO
			tokens (user_id, refresh_token_hash, expires)
		VALUES
			($1, $2, $3)
		ON CONFLICT 
			(user_id) 
		DO UPDATE
			SET refresh_token_hash = $2, expires = $3
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	args := []interface{}{user.ID, hashedRefreshToken, time.Now().Add(refreshExpiry)}

	_, err = m.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return tokens, err
	}

	return tokens, nil
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
