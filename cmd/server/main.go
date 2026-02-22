package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/pribhask/firewall-analyzer/internal/analyzer"
	"github.com/pribhask/firewall-analyzer/internal/auth"
	githubclient "github.com/pribhask/firewall-analyzer/internal/github"
	"github.com/pribhask/firewall-analyzer/internal/webhook"
)

type config struct {
	AppID          int64
	PrivateKeyPath string
	WebhookSecret  string
	Port           string
}

func loadConfig() (*config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found")
	}

	appIDStr := os.Getenv("GITHUB_APP_ID")
	if appIDStr == "" {
		return nil, fmt.Errorf("GITHUB_APP_ID environment variable is required")
	}
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
	}

	privateKeyPath := os.Getenv("GITHUB_PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		return nil, fmt.Errorf("GITHUB_PRIVATE_KEY_PATH environment variable is required")
	}

	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if webhookSecret == "" {
		return nil, fmt.Errorf("GITHUB_WEBHOOK_SECRET environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return &config{
		AppID:          appID,
		PrivateKeyPath: privateKeyPath,
		WebhookSecret:  webhookSecret,
		Port:           port,
	}, nil
}

// test commit
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key file")
	}

	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS1 private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	return privateKey, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	privateKey, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		logger.Error("failed to load private key", "error", err)
		os.Exit(1)
	}

	jwtSigner := auth.NewJWTSigner(cfg.AppID, privateKey)
	tokenProvider := auth.NewInstallationTokenProvider(jwtSigner)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	ghClient := githubclient.NewClient(httpClient, tokenProvider, logger)
	riskEngine := analyzer.NewRiskEngine()
	reporter := analyzer.NewReporter(riskEngine)
	prAnalyzer := analyzer.NewPRAnalyzer(ghClient, reporter, logger)

	webhookHandler := webhook.NewHandler(cfg.WebhookSecret, prAnalyzer, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", webhookHandler.Handle)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.Info("starting server", "port", cfg.Port)

	ctx := context.Background()
	_ = ctx

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
