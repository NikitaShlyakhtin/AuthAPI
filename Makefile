# Include variables from the .envrc file
include .envrc

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## run/api: run the cmd/auth application
.PHONY: run/api
run/api:
	go run ./cmd/api -db-dsn=${DB_DSN} -jwt-secret=${JWT_SECRET}
