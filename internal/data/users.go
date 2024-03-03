package data

import (
	"authapi/internal/validator"
	"context"
	"database/sql"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int64    `json:"user_id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Password password `json:"-"`
}

type password struct {
	plaintext *string
	hash      []byte
}

var (
	ErrDuplicateEmail    = errors.New("duplicate email")
	ErrDuplicateUsername = errors.New("duplicate username")
)

type UserModel struct {
	DB *sql.DB
}

func ValidateUser(v *validator.Validator, user *User) {
	v.Check(len(user.Username) > 0, "username", "must be provided")
	v.Check(len(user.Username) <= 50, "username", "must not be more than 100 bytes long")

	v.Check(len(user.Email) > 0, "email", "must be provided")
	v.Check(len(user.Email) <= 100, "email", "must not be more than 100 bytes long")

	v.Check(user.Password.plaintext != nil, "password", "must be provided")
	v.Check(len(*user.Password.plaintext) >= 8, "password", "must be at least 8 bytes long")
}

func (p *password) Set(plaintext string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), 12)
	if err != nil {
		return err
	}

	p.plaintext = &plaintext
	p.hash = hash

	return nil
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
