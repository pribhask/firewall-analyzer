package auth

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTSigner creates signed JWTs for GitHub App authentication.
type JWTSigner struct {
	appID      int64
	privateKey *rsa.PrivateKey
}

// NewJWTSigner creates a new JWTSigner for the given GitHub App ID and RSA private key.
func NewJWTSigner(appID int64, privateKey *rsa.PrivateKey) *JWTSigner {
	return &JWTSigner{
		appID:      appID,
		privateKey: privateKey,
	}
}

// Sign generates a signed JWT valid for 10 minutes, suitable for GitHub App API calls.
// GitHub requires the JWT to be issued at most 60 seconds in the past and expire within 10 minutes.
func (s *JWTSigner) Sign() (string, error) {
	now := time.Now()
	// Subtract 60 seconds to account for clock skew between this server and GitHub.
	issuedAt := now.Add(-60 * time.Second)
	expiresAt := now.Add(9 * time.Minute) // Stay well within the 10-minute limit.

	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    fmt.Sprintf("%d", s.appID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signed, nil
}
