package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const TypeRefresh = "refresh"

type jwtRefreshClaims struct {
	UserID    uuid.UUID `json:"user_id"`
	TokenType string    `json:"token_type"`

	SessionID uuid.UUID `json:"sid"`
	TokenID   uuid.UUID `json:"jti"`
	jwt.RegisteredClaims
}

func (t *Token) GenerateRefreshToken(userID, sessionID, tokenID uuid.UUID) (string, error) {
	now := time.Now()

	claims := jwtRefreshClaims{
		UserID:    userID,
		TokenType: TypeRefresh,
		SessionID: sessionID,
		TokenID:   tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID.String(),
			Audience:  t.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(t.refreshTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// TODO: error validator
	return token.SignedString(t.refreshSecret)
}

func (t *Token) ValidateRefreshToken(tokenStr string) (*jwtRefreshClaims, error) {
	return validateToken(tokenStr, t.refreshSecret, &jwtRefreshClaims{}, t.validRefresh)
	//TODO: session check
}

func (t *Token) validRefresh(claims *jwtRefreshClaims) error {
	if claims.UserID == uuid.Nil {
		return ErrInvalidToken
	}

	if claims.TokenType != TypeRefresh {
		return ErrInvalidTokenType
	}

	if claims.SessionID == uuid.Nil {
		return ErrInvalidToken
	}

	return t.validateCommon(&claims.RegisteredClaims)
}
