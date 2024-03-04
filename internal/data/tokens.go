package data

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenModel struct {
	DB *sql.DB
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

var (
	ErrTokenExpired = errors.New("token has expired")
)

func (m TokenModel) GenerateNewPair(user User, cfg TokenConfig) (Tokens, error) {
	var tokens Tokens

	claims := &jwt.MapClaims{
		"sub":      user.ID,
		"exp":      jwt.TimeFunc().Add(cfg.AccessExpiry).Unix(),
		"username": user.Username,
		"email":    user.Email,
	}

	accessToken, err := GenerateAccessToken(cfg.AccessSecret, claims)
	if err != nil {
		return tokens, err
	}

	tokens.AccessToken = accessToken

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return tokens, err
	}

	tokens.RefreshToken = refreshToken

	hashedRefreshToken, err := HashRefreshToken(refreshToken, cfg.RefreshSecret)
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

	args := []interface{}{user.ID, hashedRefreshToken, time.Now().Add(cfg.RefreshExpiry)}

	_, err = m.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return tokens, err
	}

	return tokens, nil
}

func GenerateAccessToken(secret string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return ss, nil
}

func GenerateRefreshToken() (string, error) {
	rb := make([]byte, 32)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rb), nil
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

func (m TokenModel) Logout(refreshToken, refreshSecret string) error {
	hashedRefreshToken, err := HashRefreshToken(refreshToken, refreshSecret)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `
		SELECT
			expires < NOW() AS has_expired
		FROM 
			tokens
		WHERE
			refresh_token_hash = $1
	`

	var hasExpired bool
	err = m.DB.QueryRowContext(ctx, query, hashedRefreshToken).Scan(&hasExpired)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrRecordNotFound
		default:
			return err
		}
	}

	if hasExpired {
		return ErrTokenExpired
	}

	query = `
		DELETE FROM 
			tokens
		WHERE
			refresh_token_hash = $1
	`

	result, err := m.DB.ExecContext(ctx, query, hashedRefreshToken)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}

func (m TokenModel) VerifyRefreshToken(token, secret string) (User, error) {
	var user User
	var hasExpired bool

	query := `
		SELECT 
			users.user_id,
			username,
			email,
			CASE 
				WHEN 
					tokens.expires < NOW() THEN TRUE 
				ELSE FALSE 
			END AS has_expired
		FROM
			users
		JOIN
			tokens ON users.user_id = tokens.user_id
		WHERE
			refresh_token_hash = $1
	`

	hashedRefreshToken, err := HashRefreshToken(token, secret)
	if err != nil {
		return user, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = m.DB.QueryRowContext(ctx, query, hashedRefreshToken).Scan(&user.ID, &user.Username, &user.Email, &hasExpired)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return user, ErrRecordNotFound
		default:
			return user, err
		}
	}

	if hasExpired {
		return user, ErrTokenExpired
	}

	return user, nil
}
