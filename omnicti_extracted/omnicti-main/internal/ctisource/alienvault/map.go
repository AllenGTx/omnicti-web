package alienvault

import (
	"domainscorer/internal/normalize"
	"time"
)

func Map(raw map[string]any, domain string) *normalize.Finding {
	pulse, ok := raw["pulse_info"].(map[string]any)
	if !ok {
		return nil
	}

	count := int(pulse["count"].(float64))

	severity := "high"
	baseScore := 75.0
	impact := "Malicious indicators found in OTX"

	if count == 0 {
		severity = "info"
		baseScore = 0.0
		impact = "No OTX pulses found (Clean)"
	}

	return &normalize.Finding{
		Source:     "alienvault",
		Asset:      domain,
		Type:       "reputation",
		Severity:   severity,
		BaseScore:  baseScore,
		ObservedAt: time.Now(),
		Evidence: map[string]any{
			"pulse_info": raw["pulse_info"],
			"tags":       []string{"otx"},
			"confidence": 0.9,
			"impact":     impact,
			"raw":        raw,
		},
	}
}
