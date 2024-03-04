package data

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type TokenModel struct {
	DB *sql.DB
}

func (m TokenModel) Insert(user User, hashedToken string, cfg TokenConfig) error {
	query := `
		INSERT INTO
			tokens (user_id, refresh_token_hash, expires)
		VALUES
			($1, $2, $3)
		ON CONFLICT 
			(user_id) 
		DO UPDATE
			SET refresh_token_hash = $2, expires = $3
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	args := []interface{}{user.ID, hashedToken, time.Now().Add(cfg.RefreshExpiry)}

	_, err := m.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	return nil
}

func (m TokenModel) Delete(hashedToken, refreshSecret string) error {
	var hasExpired bool

	query := `
		SELECT
			expires < NOW() AS has_expired
		FROM 
			tokens
		WHERE
			refresh_token_hash = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, hashedToken).Scan(&hasExpired)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrRecordNotFound
		default:
			return err
		}
	}

	if hasExpired {
		return ErrTokenExpired
	}

	query = `
		DELETE FROM 
			tokens
		WHERE
			refresh_token_hash = $1
	`

	result, err := m.DB.ExecContext(ctx, query, hashedToken)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}

func (m TokenModel) Verify(hashedToken, secret string) (User, error) {
	var user User
	var hasExpired bool

	query := `
		SELECT 
			users.user_id,
			username,
			email,
			CASE 
				WHEN 
					tokens.expires < NOW() THEN TRUE 
				ELSE FALSE 
			END AS has_expired
		FROM
			users
		JOIN
			tokens ON users.user_id = tokens.user_id
		WHERE
			refresh_token_hash = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, hashedToken).Scan(&user.ID, &user.Username, &user.Email, &hasExpired)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return user, ErrRecordNotFound
		default:
			return user, err
		}
	}

	if hasExpired {
		return user, ErrTokenExpired
	}

	return user, nil
}
