package scoring

import (
	"domainscorer/internal/normalize"
	"math"
)

// Aggregate calculates the total risk score for the domain based on all normalized findings.
// Strategy: Group by Provider, Cap each Provider at 20.0, Sum Providers, Cap Total at 100.0.
// This aligns with the AI scoring logic to prevent single-source saturation.
func Aggregate(fs []normalize.Finding) float64 {
	// 1. Group by Source
	scoresBySource := make(map[string]float64)
	for _, f := range fs {
		scoresBySource[f.Source] += ScoreFinding(f)
	}

	// 2. Sum Capped Source Scores
	totalScore := 0.0
	for _, score := range scoresBySource {
		// Cap each provider at 20.0 points (20% of total)
		contribution := math.Min(20.0, score)
		totalScore += contribution
	}

	// 3. Cap Total at 100.0
	return math.Min(100.0, totalScore)
}
