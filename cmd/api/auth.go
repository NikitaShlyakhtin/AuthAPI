package main

import (
	"authapi/internal/data"
	"authapi/internal/validator"
	"errors"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func (app *application) registerHandler(ctx *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
	}

	err := ctx.ShouldBindJSON(&input)
	if err != nil {
		app.badRequestResponse(ctx, err)
		return
	}

	user := &data.User{
		Username: input.Username,
		Email:    input.Email,
	}

	err = user.Password.SetAndHash(input.Password)
	if err != nil {
		app.serverErrorResponse(ctx, err)
		return
	}

	v := validator.New()

	if data.ValidateUser(v, user); !v.Valid() {
		app.failedValidationResponse(ctx, v.Errors)
		return
	}

	err = app.models.Users.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			app.failedValidationResponse(ctx, v.Errors)
		case errors.Is(err, data.ErrDuplicateUsername):
			v.AddError("username", "this username is already taken")
			app.failedValidationResponse(ctx, v.Errors)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	ctx.JSON(http.StatusAccepted, gin.H{"message": "user account created"})
}

func (app *application) loginHandler(ctx *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	err := ctx.ShouldBindJSON(&input)
	if err != nil {
		app.badRequestResponse(ctx, err)
		return
	}

	user := &data.User{
		Username: input.Username,
	}
	user.Password.Set(input.Password)

	err = app.models.Users.Authenticate(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrInvalidCredentials):
			app.invalidCredentialsResponse(ctx)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	tokenConfig := data.TokenConfig{
		AccessSecret:  app.config.jwt.accessSecret,
		RefreshSecret: app.config.jwt.refreshSecret,
		AccessExpiry:  app.config.jwt.accessExpiry,
		RefreshExpiry: app.config.jwt.refreshExpiry,
	}

	tokens, err := app.models.Tokens.GenerateNewPair(*user, tokenConfig)
	if err != nil {
		app.serverErrorResponse(ctx, err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

func (app *application) logoutHandler(ctx *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	err := ctx.ShouldBindJSON(&input)
	if err != nil {
		app.badRequestResponse(ctx, err)
		return
	}

	err = app.models.Tokens.Logout(input.RefreshToken, app.config.jwt.refreshSecret)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			app.invalidTokenResponse(ctx)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "refresh token revoked"})
}

func (app *application) refreshHandler(ctx *gin.Context) {}

func (app *application) verifyHandler(ctx *gin.Context) {
	var input struct {
		AccessToken string `json:"access_token" binding:"required"`
	}

	err := ctx.ShouldBindJSON(&input)
	if err != nil {
		app.badRequestResponse(ctx, err)
		return
	}

	token, err := data.ParseAccessToken(input.AccessToken, app.config.jwt.accessSecret)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrTokenExpired):
			app.tokenExpiredResponse(ctx)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	if !token.Valid {
		app.invalidTokenResponse(ctx)
		return
	}

	claims := token.Claims.(jwt.MapClaims)

	ctx.JSON(http.StatusOK, gin.H{"claims": claims})
}
