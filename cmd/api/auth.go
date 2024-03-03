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

	err = user.Password.Set(input.Password)
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

func (app *application) loginHandler(ctx *gin.Context) {}

func (app *application) logoutHandler(ctx *gin.Context) {}

func (app *application) refreshHandler(ctx *gin.Context) {}

func (app *application) verifyHandler(ctx *gin.Context) {}

func (app *application) getProfileHandler(ctx *gin.Context) {}
