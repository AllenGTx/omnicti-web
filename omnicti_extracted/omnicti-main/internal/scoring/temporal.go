package scoring

import (
	"math"
	"time"
)

// TemporalDecay calculates the freshness factor using exponential decay.
// Formula: e^(-λ * days_since_seen)
// λ (lambda) is chosen such that decay is ~0.5 after 30 days.
// λ ≈ 0.023
const lambda = 0.023

func TemporalDecay(observedAt time.Time) float64 {
	days := time.Since(observedAt).Hours() / 24.0
	if days < 0 {
		days = 0
	}
	return math.Exp(-lambda * days)
}
