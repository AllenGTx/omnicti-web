package normalize

import (
	"fmt"
	"sort"
)

// Dedup removes duplicate findings based on source, asset, and unique identifier (from evidence).
// It keeps the most recent finding.
func Dedup(findings []Finding) []Finding {
	// Map to store the latest finding for each unique key
	// Key format: Source|Asset|Type|EvidenceKey
	uniqueMap := make(map[string]Finding)

	for _, f := range findings {
		// Create a unique key for deduplication
		// We use Evidence to distinguish between different findings from the same source/asset/type
		// For example, if multiple plugins are found on LeakIX, they should be distinct functions.
		// However, if the exact same plugin is reported twice, we dedup.

		// Heuristic key generation based on Evidence
		evidenceKey := ""
		if val, ok := f.Evidence["plugin"]; ok {
			evidenceKey = fmt.Sprintf("%v", val)
		} else if val, ok := f.Evidence["port"]; ok {
			evidenceKey = fmt.Sprintf("port:%v", val)
		} else if val, ok := f.Evidence["cve"]; ok {
			evidenceKey = fmt.Sprintf("cve:%v", val)
		} else {
			// Fallback: If no distinct evidence key, maybe just Type is enough?
			// Or we can rely on hashing the Evidence map, but let's keep it simple for now based on blueprint examples.
			evidenceKey = "generic"
		}

		key := fmt.Sprintf("%s|%s|%s|%s", f.Source, f.Asset, f.Type, evidenceKey)

		if existing, exists := uniqueMap[key]; exists {
			// If existing finding is older, replace it with the new one
			if existing.ObservedAt.Before(f.ObservedAt) {
				uniqueMap[key] = f
			}
		} else {
			uniqueMap[key] = f
		}
	}

	// Convert map back to slice
	deduplicated := make([]Finding, 0, len(uniqueMap))
	for _, f := range uniqueMap {
		deduplicated = append(deduplicated, f)
	}

	// Sort explicitly for stability (optional but good for testing)
	sort.Slice(deduplicated, func(i, j int) bool {
		return deduplicated[i].BaseScore > deduplicated[j].BaseScore
	})

	return deduplicated
}
