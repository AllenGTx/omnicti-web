package abuseipdb

import (
	"domainscorer/internal/normalize"
	"time"
)

func Map(raw map[string]any, domain string) *normalize.Finding {
	data, ok := raw["data"].(map[string]any)
	if !ok {
		return nil
	}

	// Extract fields
	ipAddress, _ := data["ipAddress"].(string)
	abuseScore, _ := data["abuseConfidenceScore"].(float64)
	totalReports, _ := data["totalReports"].(float64)
	lastReported, _ := data["lastReportedAt"].(string)

	// Determine Severity and BaseScore
	// AbuseConfidenceScore is 0-100
	var severity string
	var baseScore float64
	var impact string

	if abuseScore >= 100 { // 100 is certain
		severity = "critical"
		baseScore = 100.0
		impact = "IP Address is confirmed malicious (100% confidence)"
	} else if abuseScore >= 75 {
		severity = "high"
		baseScore = 75.0 // Cap at high unless 100? Or just map directly.
		// Let's map directly to the score provided by AbuseIPDB?
		// Our internal scale is also 0-100 effectively.
		baseScore = abuseScore
		impact = "IP Address has high probability of being malicious"
	} else if abuseScore >= 50 {
		severity = "medium"
		baseScore = abuseScore
		impact = "IP Address has suspicious activity"
	} else if abuseScore > 0 {
		severity = "low"
		baseScore = abuseScore
		impact = "IP Address has been reported recently"
	} else {
		severity = "info"
		baseScore = 0.0
		impact = "IP Address is clean (0% abuse confidence)"
	}

	finding := &normalize.Finding{
		Source:     "abuseipdb",
		Asset:      domain, // We report against the domain even though checked IP
		Type:       "reputation",
		Severity:   severity,
		BaseScore:  baseScore,
		ObservedAt: time.Now(),
		Evidence: map[string]any{
			"ip_address":             ipAddress,
			"abuse_confidence_score": abuseScore,
			"total_reports":          totalReports,
			"last_reported_at":       lastReported,
			"raw":                    data,
			"impact":                 impact,
			"tags":                   []string{"abuseipdb", "ip_reputation"},
		},
	}

	return finding
}
