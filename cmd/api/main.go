package main

import (
	"authapi/internal/jsonlog"
	"flag"

	"github.com/gin-gonic/gin"
)

type config struct {
	port int
	env  string
}

type application struct {
	config config
	logger *jsonlog.Logger
}

func main() {
	var cfg config

	flag.IntVar(&cfg.port, "port", 4000, "API server port")
	flag.StringVar(&cfg.env, "mode", "debug", "Mode (debug|release)")

	if cfg.env == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	logger := jsonlog.New(gin.DefaultWriter, jsonlog.LevelInfo)

	app := &application{
		config: cfg,
		logger: logger,
	}

	err := app.serve()
	if err != nil {
		logger.PrintFatal(err, nil)
	}
}
