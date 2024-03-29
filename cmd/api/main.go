package main

import (
	"authapi/internal/data"
	"authapi/internal/jsonlog"
	"context"
	"database/sql"
	"flag"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type config struct {
	port int
	env  string
	db   struct {
		dsn string
	}
	jwt     data.TokenConfig
	limiter struct {
		rps     float64
		burst   int
		enabled bool
	}
}

type application struct {
	config config
	logger *jsonlog.Logger
	models data.Models
}

func main() {
	var cfg config

	flag.IntVar(&cfg.port, "port", 4000, "API server port")
	flag.StringVar(&cfg.env, "mode", "debug", "Mode (debug|release)")

	flag.StringVar(&cfg.db.dsn, "db-dsn", "", "PostgreSQL DSN")

	flag.StringVar(&cfg.jwt.AccessSecret, "jwt-access-secret", "", "JWT access secret key")
	flag.DurationVar(&cfg.jwt.AccessExpiry, "jwt-access-expiry", time.Minute*15, "JWT access token expiry")
	flag.DurationVar(&cfg.jwt.RefreshExpiry, "jwt-refresh-expiry", time.Hour*24*7, "JWT refresh token expiry")
	flag.StringVar(&cfg.jwt.RefreshSecret, "jwt-refresh-secret", "", "JWT refresh secret key")
	flag.IntVar(&cfg.jwt.RefreshLength, "jwt-refresh-length", 64, "JWT refresh token length")

	flag.Float64Var(&cfg.limiter.rps, "limiter-rps", 2, "Rate limiter maximum requests per second")
	flag.IntVar(&cfg.limiter.burst, "limiter-burst", 4, "Rate limiter burst")
	flag.BoolVar(&cfg.limiter.enabled, "limiter-enabled", false, "Enable rate limiter")

	flag.Parse()

	if cfg.env == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	logger := jsonlog.New(gin.DefaultWriter, jsonlog.LevelInfo)

	db, err := openDB(cfg)
	if err != nil {
		logger.PrintFatal(err, nil)
	}

	defer db.Close()

	logger.PrintInfo("database connection pool established", nil)

	app := &application{
		config: cfg,
		logger: logger,
		models: data.NewModels(db),
	}

	err = app.serve()
	if err != nil {
		logger.PrintFatal(err, nil)
	}
}

func openDB(cfg config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.db.dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}

	return db, nil
}
