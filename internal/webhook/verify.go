package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/pribhask/firewall-analyzer/internal/analyzer"
)

// PullRequestEvent is the relevant subset of GitHub's pull_request webhook payload.
type PullRequestEvent struct {
	Action       string      `json:"action"`
	Number       int         `json:"number"`
	PullRequest  PullRequest `json:"pull_request"`
	Repository   Repository  `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

type PullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"` // ← add this
	Head   Commit `json:"head"`
	Base   Commit `json:"base"`
}

// Commit represents a git commit ref in a pull request.
type Commit struct {
	SHA  string     `json:"sha"`
	Repo Repository `json:"repo"`
}

// Repository identifies a GitHub repository.
type Repository struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// Handler processes incoming GitHub webhook requests.
type Handler struct {
	secret     string
	prAnalyzer *analyzer.PRAnalyzer
	logger     *slog.Logger
}

// NewHandler creates a new webhook Handler.
func NewHandler(secret string, prAnalyzer *analyzer.PRAnalyzer, logger *slog.Logger) *Handler {
	return &Handler{
		secret:     secret,
		prAnalyzer: prAnalyzer,
		logger:     logger,
	}
}

// Handle is the HTTP handler for incoming GitHub webhook events.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		h.logger.Error("reading request body", "error", err)
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	if err := h.verifySignature(r.Header.Get("X-Hub-Signature-256"), body); err != nil {
		h.logger.Warn("webhook signature verification failed", "error", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType != "pull_request" {
		// Acknowledge non-PR events without processing.
		w.WriteHeader(http.StatusOK)
		return
	}

	var event PullRequestEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.Error("parsing webhook payload", "error", err)
		http.Error(w, "failed to parse payload", http.StatusBadRequest)
		return
	}

	// Only process relevant actions.
	if event.Action != "opened" && event.Action != "synchronize" && event.Action != "reopened" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if event.Installation.ID == 0 {
		h.logger.Error("missing installation ID in webhook payload")
		http.Error(w, "missing installation ID", http.StatusBadRequest)
		return
	}

	analyzerEvent := analyzer.PREvent{
		InstallationID: event.Installation.ID,
		Owner:          event.Repository.Owner.Login,
		Repo:           event.Repository.Name,
		PRNumber:       event.Number,
		PRTitle:        event.PullRequest.Title, // ← add this
		BaseSHA:        event.PullRequest.Base.SHA,
		HeadSHA:        event.PullRequest.Head.SHA,
	}

	// Process asynchronously to return 200 quickly to GitHub.
	go func() {
		if err := h.prAnalyzer.Analyze(r.Context(), analyzerEvent); err != nil {
			h.logger.Error("analyzing pull request",
				"error", err,
				"owner", analyzerEvent.Owner,
				"repo", analyzerEvent.Repo,
				"pr", analyzerEvent.PRNumber,
			)
		}
	}()

	w.WriteHeader(http.StatusOK)
}

// verifySignature validates the HMAC-SHA256 signature from GitHub.
// The signature header is in the format "sha256=<hex_digest>".
func (h *Handler) verifySignature(signatureHeader string, body []byte) error {
	if signatureHeader == "" {
		return fmt.Errorf("missing X-Hub-Signature-256 header")
	}

	const prefix = "sha256="
	if !strings.HasPrefix(signatureHeader, prefix) {
		return fmt.Errorf("signature header does not have sha256= prefix")
	}

	expectedSig, err := hex.DecodeString(strings.TrimPrefix(signatureHeader, prefix))
	if err != nil {
		return fmt.Errorf("decoding signature hex: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write(body)
	actualSig := mac.Sum(nil)

	if !hmac.Equal(expectedSig, actualSig) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}
