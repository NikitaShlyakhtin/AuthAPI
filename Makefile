# Include variables from the .envrc file
include .envrc

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## run/api: run the cmd/auth application
.PHONY: run/api
run/api:
	go run ./cmd/api -db-dsn=${DB_DSN} -jwt-access-secret=${JWT_ACCESS_SECRET} -jwt-refresh-secret=${JWT_REFRESH_SECRET} -limiter-enabled
