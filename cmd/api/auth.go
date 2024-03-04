package main

import (
	"authapi/internal/data"
	"authapi/internal/validator"
	"errors"
	"net/http"

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

	v := validator.New()

	if data.ValidateLoginCredentials(v, user); !v.Valid() {
		app.failedValidationResponse(ctx, v.Errors)
		return
	}

	err = app.models.Users.Login(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrInvalidCredentials):
			app.invalidCredentialsResponse(ctx)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	tokens, err := app.GenerateNewPair(*user)
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

	v := validator.New()

	if data.ValidateRefreshToken(v, input.RefreshToken, app.config.jwt.RefreshLength); !v.Valid() {
		app.failedValidationResponse(ctx, v.Errors)
		return
	}

	err = app.RevokeToken(input.RefreshToken)
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

func (app *application) refreshHandler(ctx *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	err := ctx.ShouldBindJSON(&input)
	if err != nil {
		app.badRequestResponse(ctx, err)
		return
	}

	v := validator.New()

	if data.ValidateRefreshToken(v, input.RefreshToken, app.config.jwt.RefreshLength); !v.Valid() {
		app.failedValidationResponse(ctx, v.Errors)
		return
	}

	tokens, err := app.RefreshToken(input.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			app.invalidTokenResponse(ctx)
		case errors.Is(err, data.ErrTokenExpired):
			app.tokenExpiredResponse(ctx)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

func (app *application) verifyHandler(ctx *gin.Context) {
	var input struct {
		AccessToken string `json:"access_token" binding:"required"`
	}

	err := ctx.ShouldBindJSON(&input)
	if err != nil {
		app.badRequestResponse(ctx, err)
		return
	}

	claims, err := app.VerifyToken(input.AccessToken)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrTokenExpired):
			app.tokenExpiredResponse(ctx)
		case errors.Is(err, data.ErrTokenInvalid):
			app.invalidTokenResponse(ctx)
		default:
			app.serverErrorResponse(ctx, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"claims": claims})
}
