package scoring

import (
	"domainscorer/internal/config"
	"strings"
)

// SeverityScore returns the intrinsic risk score based on severity level.
func SeverityScore(sev string) float64 {
	sev = strings.ToLower(sev)
	if val, ok := config.CurrentScoringConfig.Severity[sev]; ok {
		return val
	}
	// Fallback to "default" if present
	if val, ok := config.CurrentScoringConfig.Severity["default"]; ok {
		return val
	}
	return 0
}
