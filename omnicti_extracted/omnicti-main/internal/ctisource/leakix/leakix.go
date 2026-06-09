package leakix

import (
	"strings"
)

type Source struct {
	Options map[string]string
}

func NewSource() *Source {
	return &Source{}
}

func (s *Source) Name() string {
	return "leakix"
}

func mapPluginSeverity(plugin string) (string, float64) {
	p := strings.ToLower(plugin)

	switch {
	// 🔴 CRITICAL
	case strings.Contains(p, "dotenv"),
		strings.Contains(p, "gitconfig"),
		strings.Contains(p, "mongoopen"),
		strings.Contains(p, "redisopen"),
		strings.Contains(p, "elasticsearchopen"):
		return "critical", 100

	// 🟠 HIGH
	case strings.Contains(p, "swagger"),
		strings.Contains(p, "apachestatus"),
		strings.Contains(p, "wpuserenum"),
		strings.Contains(p, "jira"),
		strings.Contains(p, "confluence"):
		return "high", 75

	// 🟡 MEDIUM
	case strings.Contains(p, "dsstore"),
		strings.Contains(p, "directorylisting"),
		strings.Contains(p, "phpinfo"):
		return "medium", 50

	// 🔵 LOW
	default:
		return "low", 25
	}
}
