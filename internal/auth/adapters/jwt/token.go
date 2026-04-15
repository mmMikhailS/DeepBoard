package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidToken            = errors.New("invalid jwt")
	ErrInvalidTokenType        = errors.New("invalid jwt type")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrSessionRevoked          = errors.New("session has been revoked")
	ErrInternal                = errors.New("internal security check failed")
	ErrGenerateToken           = errors.New("could not generate security token")
	ErrStoreSession            = errors.New("could not persist session")
	ErrInternalServer          = errors.New("an internal error occurred")
)

type Token struct {
	issuer          string
	audience        []string
	currentAudience string
	refreshKey      string
	accessKey       string
	refreshSecret   []byte
	accessSecret    []byte
	accessTTL       time.Duration
	refreshTTL      time.Duration
	sessionRepo     SessionRepository
}

type SessionRepository interface {
	CreateSession(ctx context.Context, key string, sessionID, userID, deviceID uuid.UUID, expiry time.Time) error
	IsSessionValid(ctx context.Context, key string, sessionID uuid.UUID) (bool, error)
	InvalidateSession(ctx context.Context, sessionID uuid.UUID) error
}

func NewToken(issuer, currentAudience, accessSecret, refreshSecret, refreshKey, accessKey string, accessTTL, refreshTTL time.Duration, audience []string, repo SessionRepository) *Token {
	if len(issuer) == 0 {
		panic("issuer name is empty")
	}

	if currentAudience == "" {
		panic("current audience name is empty")
	}

	if len(audience) < 1 {
		panic("audience length is empty")
	}

	if accessSecret == "" {
		panic("access secret is empty")
	}

	if refreshSecret == "" {
		panic("refresh secret is empty")
	}

	if accessTTL == 0 {
		panic("access ttl is zero")
	}

	if refreshTTL == 0 {
		panic("refresh ttl is zero")
	}

	return &Token{
		issuer:          issuer,
		audience:        audience,
		currentAudience: currentAudience,
		refreshKey:      refreshKey,
		accessKey:       accessKey,
		refreshSecret:   []byte(refreshSecret),
		accessSecret:    []byte(accessSecret),
		accessTTL:       accessTTL,
		refreshTTL:      refreshTTL,
		sessionRepo:     repo,
	}
}

func (t *Token) GenerateTokenPair(
	ctx context.Context,
	deviceID uuid.UUID,
	sessionID uuid.UUID,
	userID uuid.UUID,
	email string,
	tokenID uuid.UUID,
	scopes []string,
) (accessToken, refreshToken string, err error) {
	accessToken, err = t.GenerateAndStoreAccessToken(ctx, deviceID, sessionID, userID, email, scopes)
	if err != nil {
		return "", "", fmt.Errorf("%w: access token: %v", ErrGenerateToken, err)
	}

	refreshToken, err = t.GenerateAndStoreRefreshToken(ctx, userID, sessionID, tokenID)
	if err != nil {
		return "", "", fmt.Errorf("%w: refresh token: %v", ErrGenerateToken, err)
	}

	return accessToken, refreshToken, nil
}
