package scoring

import (
	"domainscorer/internal/config"
	"strings"
)

// SourceReliability returns a confidence weight (0.0 - 1.0) for a given source.
func SourceReliability(source string) float64 {
	source = strings.ToLower(source)
	if val, ok := config.CurrentScoringConfig.Reliability.Sources[source]; ok {
		return val
	}
	return config.CurrentScoringConfig.Reliability.Default
}
