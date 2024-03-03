package main

import (
	"github.com/gin-gonic/gin"
)

func (app *application) routes() *gin.Engine {
	router := gin.Default()

	router.HandleMethodNotAllowed = true
	router.NoMethod(app.methodNotAllowedResponse)
	router.NoRoute(app.notFoundResponse)

	router.POST("/auth/register", app.registerHandler)
	router.GET("/auth/profile", app.getProfileHandler)
	router.POST("/auth/login", app.loginHandler)
	router.POST("/auth/logout", app.logoutHandler)
	router.POST("/auth/refresh", app.refreshHandler)
	router.POST("/auth/verify", app.verifyHandler)

	return router
}
