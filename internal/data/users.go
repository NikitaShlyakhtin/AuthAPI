package data

import (
	"authapi/internal/validator"
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrDuplicateEmail     = errors.New("duplicate email")
	ErrDuplicateUsername  = errors.New("duplicate username")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserModel struct {
	DB *sql.DB
}

type User struct {
	ID       int64    `json:"user_id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Password password `json:"-"`
}

func ValidateUser(v *validator.Validator, user *User) {
	ValidateUsername(v, user.Username)
	ValidateEmail(v, user.Email)
	ValidatePassword(v, *user.Password.plaintext)
}

func ValidateLoginCredentials(v *validator.Validator, user *User) {
	ValidateUsername(v, user.Username)
	ValidatePassword(v, *user.Password.plaintext)
}

func ValidateUsername(v *validator.Validator, username string) {
	v.Check(len(username) <= 50, "username", "must not be more than 50 bytes long")
}

func ValidateEmail(v *validator.Validator, email string) {
	v.Check(len(email) <= 100, "email", "must not be more than 100 bytes long")
}

func (m UserModel) Insert(user *User) error {
	query := `
		INSERT INTO users (username, email, password_hash)
		VALUES ($1, $2, $3)
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	args := []interface{}{user.Username, user.Email, user.Password.hash}

	_, err := m.DB.ExecContext(ctx, query, args...)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		case err.Error() == `pq: duplicate key value violates unique constraint "users_username_key"`:
			return ErrDuplicateUsername
		default:
			return err
		}
	}

	return nil
}

func (m UserModel) Login(user *User) error {
	var user_id int64
	var email string
	var hash string

	query := `
		SELECT user_id, email, password_hash
		FROM users
		WHERE username = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, user.Username).Scan(&user_id, &email, &hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidCredentials
		} else {
			return err
		}
	}

	err = verifyPassword(*user.Password.plaintext, hash)
	if err != nil {
		return ErrInvalidCredentials
	}

	user.ID = user_id
	user.Email = email

	return nil
}
