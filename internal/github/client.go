package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	apiBase    = "https://api.github.com"
	apiVersion = "2022-11-28"
)

// TokenProvider provides installation access tokens.
type TokenProvider interface {
	GetToken(ctx context.Context, installationID int64) (string, error)
}

// Client is a GitHub API client that authenticates as a GitHub App installation.
type Client struct {
	httpClient    *http.Client
	tokenProvider TokenProvider
	logger        *slog.Logger
}

// NewClient creates a new GitHub API client.
func NewClient(httpClient *http.Client, tokenProvider TokenProvider, logger *slog.Logger) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		httpClient:    httpClient,
		tokenProvider: tokenProvider,
		logger:        logger,
	}
}

// PRFile represents a file changed in a pull request.
type PRFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"` // added, removed, modified, renamed
	SHA      string `json:"sha"`
}

// FileContent represents the raw content of a file from GitHub.
type FileContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	SHA      string `json:"sha"`
}

// GetPRFiles returns the list of files changed in a pull request.
func (c *Client) GetPRFiles(ctx context.Context, installationID int64, owner, repo string, prNumber int) ([]PRFile, error) {
	token, err := c.tokenProvider.GetToken(ctx, installationID)
	if err != nil {
		return nil, fmt.Errorf("getting installation token: %w", err)
	}

	// GitHub paginates PR files with max 30 per page; fetch up to 300 files.
	var allFiles []PRFile
	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=30&page=%d",
			apiBase, owner, repo, prNumber, page)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}

		c.setHeaders(req, token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("executing request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d fetching PR files", resp.StatusCode)
		}

		var files []PRFile
		if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
			return nil, fmt.Errorf("decoding PR files response: %w", err)
		}

		allFiles = append(allFiles, files...)

		if len(files) < 30 {
			break
		}
	}

	return allFiles, nil
}

// GetFileContent fetches the raw content of a file at a specific commit SHA.
// Returns nil content (no error) if the file does not exist at that ref (404).
func (c *Client) GetFileContent(ctx context.Context, installationID int64, owner, repo, path, ref string) ([]byte, error) {
	token, err := c.tokenProvider.GetToken(ctx, installationID)
	if err != nil {
		return nil, fmt.Errorf("getting installation token: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		apiBase, owner, repo, path, ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.setHeaders(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching file content for %s@%s", resp.StatusCode, path, ref)
	}

	var content FileContent
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, fmt.Errorf("decoding file content response: %w", err)
	}

	if content.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q for file %s", content.Encoding, path)
	}

	// GitHub base64-encodes file contents with newlines; strip them before decoding.
	decoded, err := base64.StdEncoding.DecodeString(removeNewlines(content.Content))
	if err != nil {
		return nil, fmt.Errorf("decoding base64 content for %s: %w", path, err)
	}

	return decoded, nil
}

// PostComment creates a comment on a pull request.
func (c *Client) PostComment(ctx context.Context, installationID int64, owner, repo string, prNumber int, body string) error {
	token, err := c.tokenProvider.GetToken(ctx, installationID)
	if err != nil {
		return fmt.Errorf("getting installation token: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", apiBase, owner, repo, prNumber)

	payload := struct {
		Body string `json:"body"`
	}{Body: body}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling comment payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		newBytesReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	c.setHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status %d posting comment", resp.StatusCode)
	}

	return nil
}

func (c *Client) setHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
}

func removeNewlines(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' && s[i] != '\r' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
