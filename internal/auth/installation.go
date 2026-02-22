package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const githubAPIBase = "https://api.github.com"

// installationToken holds a cached installation access token and its expiration time.
type installationToken struct {
	token     string
	expiresAt time.Time
}

func (t *installationToken) isValid() bool {
	// Treat token as expired 5 minutes before actual expiry to avoid edge cases.
	return time.Now().Before(t.expiresAt.Add(-5 * time.Minute))
}

// InstallationTokenProvider exchanges GitHub App JWTs for installation access tokens
// and caches them per installation ID.
type InstallationTokenProvider struct {
	signer     *JWTSigner
	httpClient *http.Client
	mu         sync.Mutex
	cache      map[int64]*installationToken
}

// NewInstallationTokenProvider creates a new InstallationTokenProvider.
func NewInstallationTokenProvider(signer *JWTSigner) *InstallationTokenProvider {
	return &InstallationTokenProvider{
		signer:     signer,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      make(map[int64]*installationToken),
	}
}

// installationTokenResponse is the JSON response from GitHub's installation token endpoint.
type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetToken returns a valid installation access token for the given installation ID.
// Tokens are cached and automatically refreshed when expired.
func (p *InstallationTokenProvider) GetToken(ctx context.Context, installationID int64) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if cached, ok := p.cache[installationID]; ok && cached.isValid() {
		return cached.token, nil
	}

	jwtToken, err := p.signer.Sign()
	if err != nil {
		return "", fmt.Errorf("generating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", githubAPIBase, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status %d from installation token endpoint", resp.StatusCode)
	}

	var tokenResp installationTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("received empty token from GitHub")
	}

	p.cache[installationID] = &installationToken{
		token:     tokenResp.Token,
		expiresAt: tokenResp.ExpiresAt,
	}

	return tokenResp.Token, nil
}
