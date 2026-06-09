package ipinfo

import (
	"domainscorer/internal/normalize"
	"fmt"
	"time"
)

func Map(raw map[string]any, domain string) *normalize.Finding {
	// Extract fields
	ip, _ := raw["ip"].(string)
	city, _ := raw["city"].(string)
	region, _ := raw["region"].(string)
	country, _ := raw["country"].(string)
	org, _ := raw["org"].(string)

	// IPInfo is primarily context, usually "info" severity
	// UNLESS we want to flag specific high-risk countries?
	// For now, let's keep it as INFO / context.

	severity := "info"
	baseScore := 0.0
	impact := fmt.Sprintf("Hosting Location: %s, %s (%s)", city, country, org)

	finding := &normalize.Finding{
		Source:     "ipinfo",
		Asset:      domain,
		Type:       "context", // New type for context-only findings? Or use standard?
		Severity:   severity,
		BaseScore:  baseScore,
		ObservedAt: time.Now(),
		Evidence: map[string]any{
			"ip":      ip,
			"city":    city,
			"region":  region,
			"country": country,
			"org":     org,
			"impact":  impact,
			"raw":     raw,
		},
	}

	return finding
}
