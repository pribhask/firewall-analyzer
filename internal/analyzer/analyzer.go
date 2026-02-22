package analyzer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	githubclient "github.com/pribhask/firewall-analyzer/internal/github"
	"github.com/pribhask/firewall-analyzer/internal/terraform"
)

// PREvent holds the data needed to analyze a pull request.
type PREvent struct {
	InstallationID int64
	Owner          string
	Repo           string
	PRNumber       int
	BaseSHA        string
	HeadSHA        string
}

// PRAnalyzer orchestrates the analysis of pull request changes.
type PRAnalyzer struct {
	ghClient *githubclient.Client
	reporter *Reporter
	parser   *terraform.Parser
	differ   *terraform.Differ
	logger   *slog.Logger
}

// NewPRAnalyzer creates a new PRAnalyzer with all required dependencies.
func NewPRAnalyzer(ghClient *githubclient.Client, reporter *Reporter, logger *slog.Logger) *PRAnalyzer {
	return &PRAnalyzer{
		ghClient: ghClient,
		reporter: reporter,
		parser:   terraform.NewParser(),
		differ:   terraform.NewDiffer(),
		logger:   logger,
	}
}

// Analyze performs the full analysis pipeline for a pull request event.
func (a *PRAnalyzer) Analyze(ctx context.Context, event PREvent) error {
	a.logger.Info("starting PR analysis",
		"owner", event.Owner,
		"repo", event.Repo,
		"pr", event.PRNumber,
		"base_sha", event.BaseSHA,
		"head_sha", event.HeadSHA,
	)

	files, err := a.ghClient.GetPRFiles(ctx, event.InstallationID, event.Owner, event.Repo, event.PRNumber)
	if err != nil {
		return fmt.Errorf("fetching PR files: %w", err)
	}

	var tfFiles []githubclient.PRFile
	for _, f := range files {
		if strings.HasSuffix(f.Filename, ".tf") {
			tfFiles = append(tfFiles, f)
		}
	}

	if len(tfFiles) == 0 {
		a.logger.Info("no .tf files changed, skipping analysis")
		return nil
	}

	var fileDiffs []FileDiff

	for _, f := range tfFiles {
		diff, err := a.analyzeFile(ctx, event, f)
		if err != nil {
			a.logger.Warn("error analyzing file",
				"file", f.Filename,
				"error", err,
			)
			// Continue with remaining files rather than aborting.
			continue
		}

		if !diff.HasFirewall {
			continue
		}

		score := a.reporter.riskEngine.Score(diff)
		fileDiffs = append(fileDiffs, FileDiff{
			Filename: f.Filename,
			Diff:     diff,
			Score:    score,
		})

		a.logger.Info("file analyzed",
			"file", f.Filename,
			"changes", len(diff.Changes),
			"risk_score", score.Score,
		)
	}

	if len(fileDiffs) == 0 {
		a.logger.Info("no firewall-related changes found")
		return nil
	}

	report := a.reporter.Aggregate(fileDiffs)
	comment := a.reporter.GenerateComment(report)

	if comment == "" {
		return nil
	}

	if err := a.ghClient.PostComment(ctx, event.InstallationID, event.Owner, event.Repo, event.PRNumber, comment); err != nil {
		return fmt.Errorf("posting PR comment: %w", err)
	}

	a.logger.Info("analysis complete and comment posted",
		"overall_risk", report.TotalScore.Score,
		"level", report.TotalScore.Level,
	)

	return nil
}

func (a *PRAnalyzer) analyzeFile(ctx context.Context, event PREvent, file githubclient.PRFile) (*terraform.DiffResult, error) {
	var beforeContent, afterContent []byte
	var err error

	// Fetch before content (base SHA). Deleted files return nil.
	if file.Status != "added" {
		beforeContent, err = a.ghClient.GetFileContent(ctx, event.InstallationID, event.Owner, event.Repo, file.Filename, event.BaseSHA)
		if err != nil {
			return nil, fmt.Errorf("fetching base content for %s: %w", file.Filename, err)
		}
	}

	// Fetch after content (head SHA). Deleted files return nil.
	if file.Status != "removed" {
		afterContent, err = a.ghClient.GetFileContent(ctx, event.InstallationID, event.Owner, event.Repo, file.Filename, event.HeadSHA)
		if err != nil {
			return nil, fmt.Errorf("fetching head content for %s: %w", file.Filename, err)
		}
	}

	var beforeParsed, afterParsed *terraform.RuleGroupFile

	if len(beforeContent) > 0 {
		beforeParsed, err = a.parser.ParseFile(file.Filename+"@base", beforeContent)
		if err != nil {
			return nil, fmt.Errorf("parsing base version of %s: %w", file.Filename, err)
		}
	}

	if len(afterContent) > 0 {
		afterParsed, err = a.parser.ParseFile(file.Filename+"@head", afterContent)
		if err != nil {
			return nil, fmt.Errorf("parsing head version of %s: %w", file.Filename, err)
		}
	}

	diff, err := a.differ.Diff(beforeParsed, afterParsed)
	if err != nil {
		return nil, fmt.Errorf("computing diff for %s: %w", file.Filename, err)
	}

	return diff, nil
}
