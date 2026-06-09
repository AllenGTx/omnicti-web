package leakix

import (
	"domainscorer/internal/normalize"
	"fmt"
	"time"
)

const maxAgeDays = 90

func (s *Source) Map(raw any, asset string) ([]normalize.Finding, error) {
	items, ok := raw.([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid raw data type for leakix.Map")
	}

	var findings []normalize.Finding

	for _, item := range items {
		// The /domain/ endpoint returns Leaks as a list of Hosts, which contain "events".
		// Structure: [{"Ip": "...", "events": [{...}, {...}]}]
		// We need to iterate over these events.

		rawEvents, ok := item["events"].([]interface{})
		if !ok {
			continue
		}

		for _, e := range rawEvents {
			rawLeak, ok := e.(map[string]interface{})
			if !ok {
				continue
			}

			// --- time ---
			ts, ok := rawLeak["time"].(string)
			if !ok {
				continue
			}

			t, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil {
				t, err = time.Parse(time.RFC3339, ts)
				if err != nil {
					continue
				}
			}

			// Filter old data
			if time.Since(t) > maxAgeDays*24*time.Hour {
				continue
			}

			// Map Fields
			// LeakIX v2/v3 uses "event_source" for the plugin name
			plugin, _ := rawLeak["event_source"].(string)
			summary, _ := rawLeak["summary"].(string)

			// Host usually in "host" or "ip" logic, but "host" key exists in event
			host, _ := rawLeak["host"].(string)
			if host == "" {
				host = asset
			}

			severity, baseScore := mapPluginSeverity(plugin)

			findings = append(findings, normalize.Finding{
				Source:     "leakix",
				Type:       "misconfiguration",
				Severity:   severity,
				BaseScore:  baseScore,
				ObservedAt: t,
				Asset:      host,
				Evidence: map[string]any{
					"plugin":  plugin,
					"summary": summary,
				},
			})
		}
	}

	return findings, nil
}
