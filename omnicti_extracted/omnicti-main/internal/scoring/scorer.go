package scoring

import (
	"domainscorer/internal/normalize"
)

// ScoreFinding calculates the final risk score for a single finding.
// Formula: BaseScore * Multiplier * TemporalDecay * SourceReliability
func ScoreFinding(f normalize.Finding) float64 {
	// BaseScore should already be populated from the mapping phase
	base := f.BaseScore
	if base == 0 {
		base = SeverityScore(f.Severity)
	}

	// Apply Business Logic Multiplier if not already set (or purely calculated here)
	// Ideally, it might be set during mapping, but calculating it here ensures consistency.
	// However, if we follow the paper strictly, the framework incorporates it.
	// Let's deduce it if it's 0 (default).
	multiplier := f.Multiplier
	if multiplier == 0 {
		multiplier = BusinessLogicMultiplier(f.Type, f.Evidence)
	}

	decay := TemporalDecay(f.ObservedAt)
	reliability := SourceReliability(f.Source)

	return base * multiplier * decay * reliability
}
