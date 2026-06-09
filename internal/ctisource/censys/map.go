package censys

import (
	"domainscorer/internal/normalize"
	"fmt"
	"time"
)

func (s *Source) Map(raw any, mainDomain string) ([]normalize.Finding, error) {
	data, ok := raw.(map[string]any)
	if !ok {
		return nil, nil
	}

	var findings []normalize.Finding

	// Process V3 Hosts
	if hostsRaw, ok := data["v3_hosts"]; ok {
		if hosts, ok := hostsRaw.([]V3Resource); ok {
			for _, host := range hosts {
				for _, svc := range host.Services {
					// Scan Time for ObservedAt
					ts, err := time.Parse(time.RFC3339, svc.ScanTime)
					if err != nil {
						ts = time.Now()
					}

					assetName := fmt.Sprintf("%s:%d", host.IP, svc.Port)

					// 1. Exposure Finding
					baseScore := 10 // Info default
					severity := "info"
					multiplier := 1.0

					switch svc.Port {
					case 80, 443, 8080, 8443:
						// Normal Web
					case 21, 22, 23, 3389, 5900:
						// Admin / Remote Access
						baseScore = 75
						severity = "high"
						multiplier = 1.2
					case 3306, 5432, 6379, 27017, 1433:
						// Database
						baseScore = 75
						severity = "high"
						multiplier = 1.3
					}

					// Add finding
					findings = append(findings, normalize.Finding{
						Source:     "censys",
						Type:       "exposure",
						Severity:   severity,
						BaseScore:  float64(baseScore),
						Multiplier: multiplier,
						ObservedAt: ts,
						Asset:      assetName,
						Evidence: map[string]any{
							"ip":        host.IP,
							"port":      svc.Port,
							"service":   svc.Protocol,
							"transport": svc.TransportProtocol,
						},
					})

					// 2. TLS Analysis
					if svc.TLS != nil {
						// Record observation of certificate
						for _, chain := range svc.TLS.PresentedChain {
							findings = append(findings, normalize.Finding{
								Source:     "censys",
								Type:       "exposure",
								Severity:   "info",
								BaseScore:  10,
								ObservedAt: ts,
								Asset:      assetName,
								Evidence: map[string]any{
									"issue":       "certificate_observation",
									"fingerprint": chain.FingerprintSHA256,
									"subject":     chain.SubjectDN,
									"issuer":      chain.IssuerDN,
								},
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}
