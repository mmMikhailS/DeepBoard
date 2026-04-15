package auth

import (
	"errors"
	"strings"
	"time"
)

type User struct {
	id           string
	createdAt    time.Time
	email        string
	name         string
	passwordHash string
}

func NewUser(id, email, name, passwordHash string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	name = strings.TrimSpace(name)

	if id == "" {
		return nil, errors.New("id is required")
	}
	if email == "" || !strings.Contains(email, "@") {
		return nil, errors.New("invalid email")
	}
	if name == "" {
		return nil, errors.New("name is required")
	}
	if passwordHash == "" {
		return nil, errors.New("password hash is required")
	}

	return &User{
		id:           id,
		email:        email,
		name:         name,
		passwordHash: passwordHash,
	}, nil
}

func (u *User) ID() string {
	return u.id
}

func (u *User) CreatedAt() time.Time {
	return u.createdAt
}

func (u *User) Email() string {
	return u.email
}

func (u *User) Name() string {
	return u.name
}

func (u *User) PasswordHash() string {
	return u.passwordHash
}
