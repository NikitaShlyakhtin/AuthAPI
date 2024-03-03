package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (app *application) logError(ctx *gin.Context, err error) {
	app.logger.PrintError(err, map[string]string{
		"request_method": ctx.Request.Method,
		"request_url":    ctx.Request.URL.String(),
	})
}

func (app *application) errorResponse(ctx *gin.Context, status int, message interface{}) {
	env := gin.H{"error": message}

	ctx.JSON(status, env)
}

func (app *application) serverErrorResponse(ctx *gin.Context, err error) {
	app.logError(ctx, err)

	message := "the server encountered a problem and could not process your request"
	app.errorResponse(ctx, http.StatusInternalServerError, message)
}

func (app *application) notFoundResponse(ctx *gin.Context) {
	message := "the requested resource could not be found"
	app.errorResponse(ctx, http.StatusNotFound, message)
}

func (app *application) methodNotAllowedResponse(ctx *gin.Context) {
	message := fmt.Sprintf("the %s method is not supported for this resource", ctx.Request.Method)
	app.errorResponse(ctx, http.StatusMethodNotAllowed, message)
}

func (app *application) badRequestResponse(ctx *gin.Context, err error) {
	app.errorResponse(ctx, http.StatusBadRequest, err.Error())
}

func (app *application) failedValidationResponse(ctx *gin.Context, errors map[string]string) {
	app.errorResponse(ctx, http.StatusUnprocessableEntity, errors)
}

func (app *application) invalidCredentialsResponse(ctx *gin.Context) {
	message := "invalid authentication credentials"
	app.errorResponse(ctx, http.StatusUnauthorized, message)
}

func (app *application) invalidTokenResponse(ctx *gin.Context) {
	message := "the token provided is not valid"
	app.errorResponse(ctx, http.StatusUnauthorized, message)
}

func (app *application) tokenExpiredResponse(ctx *gin.Context) {
	message := "the token provided has expired"
	app.errorResponse(ctx, http.StatusUnauthorized, message)
}
