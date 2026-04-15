package app

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mmMikhailS/DeepBoard/internal/auth/domain/user"
	"github.com/mmMikhailS/DeepBoard/internal/common/decorator"
	"github.com/mmMikhailS/DeepBoard/internal/common/errors"
	"github.com/sirupsen/logrus"
)

type RegisterUser struct {
	Email    string
	Password string
	Name     string
}

type RegisterUserHandler decorator.CommandHandler[RegisterUser]

type registerUserHandler struct {
	userRepo       user.Repository
	passwordHasher PasswordHasher
	tokenService   jwt.Token
}

type PasswordHasher interface {
	HashPassword(password string) (string, error)
}

type TokenService interface {
	GenerateTokenPair() (refresh, access string, err error)
}

func NewRegisterUserHandler(
	userRepo user.Repository,
	passwordHasher PasswordHasher,
	logger *logrus.Entry,
	metricsClient decorator.MetricsClient,
) RegisterUserHandler {
	if userRepo == nil {
		panic("nil userRepo")
	}
	if passwordHasher == nil {
		panic("nil passwordHasher")
	}

	return decorator.ApplyCommandDecorators[RegisterUser](
		registerUserHandler{
			userRepo:       userRepo,
			passwordHasher: passwordHasher,
		},
		logger,
		metricsClient,
	)
}

func (h registerUserHandler) Handle(ctx context.Context, cmd RegisterUser) error {
	exists, err := h.userRepo.ExistsByEmail(ctx, cmd.Email)
	if err != nil {
		return err
	}
	if exists {
		// TODO: error:
		return errors.NewSlugError("user-already-exists", "user-already-exists")
	}

	hashedPassword, err := h.passwordHasher.HashPassword(cmd.Password)
	if err != nil {
		return errors.NewSlugError(err.Error(), "unable-to-hash-password")
	}

	u, err := user.NewUser(cmd.Email, cmd.Name, hashedPassword)
	if err != nil {
		return errors.NewSlugError(err.Error(), "unable-to-create-user")
	}

	if err := h.userRepo.Save(ctx, u); err != nil {
		return errors.NewSlugError(err.Error(), "unable-to-save-user")
	}
	// TODO: generate tokens
	return nil
}
