package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const TypeAccess = "access"

type jwtAccessClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
	//Roles     []string `json:"roles,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	TokenType string   `json:"token_type"`

	SessionID uuid.UUID `json:"sid,omitempty"`
	DeviceID  uuid.UUID `json:"device_id,omitempty"`

	jwt.RegisteredClaims
}

func (t *Token) GenerateAccessToken(deviceID, sessionID, userID uuid.UUID, email string) (string, error) {
	now := time.Now()

	claims := jwtAccessClaims{
		UserID:    userID,
		Email:     email,
		Scopes:    nil,
		TokenType: TypeAccess,
		SessionID: sessionID,
		DeviceID:  deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID.String(),
			Audience:  t.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(t.accessTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// TODO: error validator
	return token.SignedString(t.accessSecret)
}

func (t *Token) ValidateAccessToken(tokenStr string) (*jwtAccessClaims, error) {
	return validateToken(tokenStr, t.accessSecret, &jwtAccessClaims{}, t.validAccess)
	// TODO: session check
}

func (t *Token) validAccess(claims *jwtAccessClaims) error {
	if claims.UserID == uuid.Nil {
		return ErrInvalidToken
	}

	if claims.TokenType != TypeAccess {
		return ErrInvalidTokenType
	}

	if claims.SessionID == uuid.Nil {
		return ErrInvalidToken
	}

	return t.validateCommon(&claims.RegisteredClaims)
}
