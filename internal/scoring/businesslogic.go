package scoring

import (
	"domainscorer/internal/config"
	"strings"
)

// BusinessLogicMultiplier calculates the impact multiplier based on potential business logic exposure.
// Paper Range: 1.2 - 2.0
func BusinessLogicMultiplier(findingType string, evidence map[string]any) float64 {
	// Look for keywords in finding evidence/summary
	var keywords string
	if val, ok := evidence["plugin"]; ok {
		keywords += strings.ToLower(val.(string))
	}
	if val, ok := evidence["product"]; ok {
		keywords += strings.ToLower(val.(string))
	}
	if val, ok := evidence["title"]; ok {
		keywords += strings.ToLower(val.(string))
	}

	// Iterate over rules from config
	// High priority rules should be first in the list
	for _, rule := range config.CurrentScoringConfig.BusinessLogic.Rules {
		for _, k := range rule.Keywords {
			if strings.Contains(keywords, k) {
				return rule.Multiplier
			}
		}
	}

	if config.CurrentScoringConfig.BusinessLogic.DefaultMultiplier > 0 {
		return config.CurrentScoringConfig.BusinessLogic.DefaultMultiplier
	}
	return 1.0
}
