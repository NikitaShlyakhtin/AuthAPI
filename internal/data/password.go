package data

import (
	"authapi/internal/validator"

	"golang.org/x/crypto/bcrypt"
)

type password struct {
	plaintext *string
	hash      []byte
}

func ValidatePassword(v *validator.Validator, password string) {
	v.Check(len(password) >= 8, "password", "must be at least 8 bytes long")
	v.Check(len(password) <= 72, "password", "must not be more that 72 long")
}

func (p *password) SetAndHash(plaintext string) error {
	hash, err := hashPassword(plaintext)
	if err != nil {
		return err
	}

	p.plaintext = &plaintext
	p.hash = hash

	return nil
}

func (p *password) Set(plaintext string) {
	p.plaintext = &plaintext
}

func hashPassword(plaintext string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(plaintext), 12)
}

func verifyPassword(plaintext, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
