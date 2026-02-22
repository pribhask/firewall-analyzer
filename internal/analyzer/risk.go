package analyzer

import (
	"math"

	"github.com/firewall-analyzer/internal/terraform"
)

// RiskLevel categorizes the overall risk score range.
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
)

// RiskScore holds the computed risk score and classification.
type RiskScore struct {
	Score float64
	Level RiskLevel
	// MaxScore is the maximum possible score (always 10).
	MaxScore float64
}

// RiskEngine computes risk scores for firewall change sets.
type RiskEngine struct{}

// NewRiskEngine creates a new RiskEngine.
func NewRiskEngine() *RiskEngine {
	return &RiskEngine{}
}

// Score computes a risk score in the range [0, 10] from a DiffResult.
// The scoring model:
//   - Accumulates risk contributions from individual changes.
//   - Applies diminishing returns via logarithm to avoid overflow.
//   - Normalizes to a 0–10 scale.
func (e *RiskEngine) Score(diff *terraform.DiffResult) RiskScore {
	if len(diff.Changes) == 0 {
		return RiskScore{Score: 0, Level: RiskLevelLow, MaxScore: 10}
	}

	raw := 0.0
	for _, change := range diff.Changes {
		raw += change.RiskContribution
	}

	// Apply diminishing returns: log1p normalizes large sums while preserving ordering.
	// Scale factor chosen so that a raw score of 20 maps to approximately 9.5.
	normalized := (math.Log1p(raw) / math.Log1p(20)) * 10
	score := math.Min(10, math.Round(normalized*10)/10)

	return RiskScore{
		Score:    score,
		Level:    classifyRisk(score),
		MaxScore: 10,
	}
}

func classifyRisk(score float64) RiskLevel {
	switch {
	case score >= 8:
		return RiskLevelCritical
	case score >= 6:
		return RiskLevelHigh
	case score >= 3:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}
