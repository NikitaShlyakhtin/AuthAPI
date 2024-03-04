package main

import (
	"authapi/internal/data"

	"github.com/dgrijalva/jwt-go"
)

func (app *application) GenerateNewPair(user data.User) (data.Tokens, error) {
	var tokens data.Tokens

	err := tokens.Generate(user, app.config.jwt)
	if err != nil {
		return tokens, err
	}

	hashedToken, err := data.HashRefreshToken(tokens.RefreshToken, app.config.jwt.RefreshSecret)
	if err != nil {
		return tokens, err
	}

	err = app.models.Tokens.Insert(user, hashedToken, app.config.jwt)
	if err != nil {
		return tokens, err
	}

	return tokens, nil
}

func (app *application) RevokeToken(token string) error {
	hashedToken, err := data.HashRefreshToken(token, app.config.jwt.RefreshSecret)
	if err != nil {
		return err
	}

	err = app.models.Tokens.Delete(hashedToken, app.config.jwt.RefreshSecret)
	if err != nil {
		return err
	}

	return nil
}

func (app *application) RefreshToken(token string) (data.Tokens, error) {
	var tokens data.Tokens

	hashedToken, err := data.HashRefreshToken(token, app.config.jwt.RefreshSecret)
	if err != nil {
		return tokens, err
	}

	user, err := app.models.Tokens.Verify(hashedToken, app.config.jwt.RefreshSecret)
	if err != nil {
		return tokens, err
	}

	tokens, err = app.GenerateNewPair(user)
	if err != nil {
		return tokens, err
	}

	return tokens, nil
}

func (app *application) VerifyToken(accessToken string) (jwt.Claims, error) {
	token, err := data.ParseAccessToken(accessToken, app.config.jwt.AccessSecret)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, data.ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, data.ErrTokenInvalid
	}

	return claims, nil
}
