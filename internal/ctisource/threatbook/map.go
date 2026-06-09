package threatbook

import (
	"domainscorer/internal/normalize"
	"strings"
	"time"
)

func Map(raw map[string]any, domain string) *normalize.Finding {
	data, ok := raw["data"].(map[string]any)
	if !ok {
		return nil
	}

	// The API returns data keyed by the IP, so we need to extract that dynamically or assume single IP query
	// Since we query one IP, let's try to find it.
	// Actually, the structure is usually {"data": {"<ip>": {...}}}
	// Let's iterate over `data` to find the IP object.
	var ipData map[string]any
	var ipAddr string

	for k, v := range data {
		if vMap, ok := v.(map[string]any); ok {
			ipAddr = k
			ipData = vMap
			break
		}
	}

	if ipData == nil {
		return nil
	}

	severityStr, _ := ipData["severity"].(string)
	judgments, _ := ipData["judgments"].([]any)
	tags, _ := ipData["tags_classes"].([]any) // or "tags" depending on API version, sticking to v3 common

	var severity string
	var baseScore float64
	var impact string

	switch strings.ToLower(severityStr) {
	case "critical":
		severity = "critical"
		baseScore = 100.0
		impact = "High condifence malicious IP involved in critical threats"
	case "high":
		severity = "high"
		baseScore = 80.0
		impact = "High confidence malicious IP"
	case "medium":
		severity = "medium"
		baseScore = 50.0
		impact = "Suspicious IP with some malicious history"
	case "low":
		severity = "low"
		baseScore = 20.0
		impact = "Low risk IP"
	default: // "info" or clean
		severity = "info"
		baseScore = 0.0
		impact = "Clean IP"
	}

	finding := &normalize.Finding{
		Source:     "threatbook",
		Asset:      domain,
		Type:       "reputation",
		Severity:   severity,
		BaseScore:  baseScore,
		ObservedAt: time.Now(),
		Evidence: map[string]any{
			"ip_address": ipAddr,
			"severity":   severityStr,
			"judgments":  judgments,
			"tags":       tags,
			"impact":     impact,
			"raw":        ipData,
		},
	}

	return finding
}
