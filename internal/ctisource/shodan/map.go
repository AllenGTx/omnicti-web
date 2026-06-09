package shodan

import (
	"domainscorer/internal/normalize"
	"time"
)

func (s *Source) Map(raw any, asset string) ([]normalize.Finding, error) {
	matches, ok := raw.([]struct {
		IPStr     string                 `json:"ip_str"`
		Port      int                    `json:"port"`
		Domains   []string               `json:"domains"`
		Hostnames []string               `json:"hostnames"`
		Data      string                 `json:"data"`
		Product   string                 `json:"product"`
		Vulns     map[string]interface{} `json:"vulns"`
		Timestamp string                 `json:"timestamp"`
	})

	if !ok {
		// Just in case it's nil (API key missing) or wrong type
		return nil, nil
	}

	var findings []normalize.Finding

	for _, m := range matches {
		ts, _ := time.Parse("2006-01-02T15:04:05.000000", m.Timestamp)
		if ts.IsZero() {
			ts = time.Now() // Fallback
		}

		// 1. Service Exposure Finding
		findings = append(findings, normalize.Finding{
			Source:     "shodan",
			Type:       "exposure",
			Severity:   "info", // Port open itself is info/low usually unless specific service
			BaseScore:  10,
			ObservedAt: ts,
			Asset:      m.IPStr,
			Evidence: map[string]any{
				"port":    m.Port,
				"product": m.Product,
				"data":    m.Data, // banner
			},
		})

		// 2. Vulnerabilities Finding (if any)
		for cve := range m.Vulns {
			findings = append(findings, normalize.Finding{
				Source:     "shodan-verified",
				Type:       "vulnerability",
				Severity:   "high", // CVE presence is usually high/critical
				BaseScore:  75,     // Or map based on CVSS if available (Shodan sometimes provides it separately)
				ObservedAt: ts,
				Asset:      m.IPStr,
				Evidence: map[string]any{
					"cve":     cve,
					"port":    m.Port,
					"product": m.Product,
				},
			})
		}
	}

	return findings, nil
}
