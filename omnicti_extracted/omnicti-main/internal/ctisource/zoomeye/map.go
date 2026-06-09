package zoomeye

import (
	"domainscorer/internal/normalize"
	"time"
)

func Map(raw map[string]any, domain string) []normalize.Finding {
	matches, ok := raw["matches"].([]any)
	if !ok || len(matches) == 0 {
		return []normalize.Finding{{
			Source:     "zoomeye",
			Asset:      domain,
			Type:       "info",
			Severity:   "info",
			BaseScore:  0,
			ObservedAt: time.Now(),
			Evidence: map[string]any{
				"message": "No results found in ZoomEye (Clean)",
			},
		}}
	}

	var findings []normalize.Finding
	for _, m := range matches {
		match, ok := m.(map[string]any)
		if !ok {
			continue
		}

		ip, _ := match["ip"].(string)
		portinfo, _ := match["portinfo"].(map[string]any)
		port, _ := portinfo["port"].(float64)
		service, _ := portinfo["service"].(string)

		findings = append(findings, normalize.Finding{
			Source:     "zoomeye",
			Asset:      ip,
			Type:       "exposure",
			Severity:   "medium", // Default for open ports
			BaseScore:  50.0,
			ObservedAt: time.Now(),
			Evidence: map[string]any{
				"port":    port,
				"service": service,
				"raw":     match,
			},
		})
	}

	return findings
}
