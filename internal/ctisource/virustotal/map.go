package virustotal

import (
	"domainscorer/internal/normalize"
	"time"
)

func (s *Source) Map(raw any, asset string) ([]normalize.Finding, error) {
	resp, ok := raw.(VTResponse)
	if !ok {
		return nil, nil
	}

	ts := time.Unix(resp.Data.Attributes.LastAnalysisDate, 0)
	var severity string
	var baseScore float64

	stats := resp.Data.Attributes.LastAnalysisStats
	malicious := stats["malicious"]
	// suspicious := stats["suspicious"] // Unused

	// Heuristic for severity
	if malicious > 5 {
		severity = "critical"
		baseScore = 90.0
	} else if malicious > 0 {
		severity = "high"
		baseScore = 75.0
	} else {
		// Clean / Info
		severity = "info"
		baseScore = 0.0
	}

	return []normalize.Finding{{
		Source:     "virustotal",
		Type:       "reputation",
		Severity:   severity,
		BaseScore:  baseScore,
		ObservedAt: ts,
		Asset:      asset,
		Evidence: map[string]any{
			"stats":      stats,
			"reputation": resp.Data.Attributes.Reputation,
		},
	}}, nil
}
